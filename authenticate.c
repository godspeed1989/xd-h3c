#include "authenticate.h"

/**
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */
int Authentication(char *UserName,char *Password,char *DeviceName)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*adhandle; // adapter handle
	uint8_t	MAC[6];
	char	FilterStr[100];
	struct bpf_program fcode;
	int DefaultTimeout = 1000;	//设置接收超时参数，单位ms

	/* 检查网线是否已插好,网线插口可能接触不良 */
	if(GetNetState(DeviceName)==-1)
	{
		fprintf(stderr, "%s\n", "网卡异常！请检查网卡名称是否正确，网线是否插好！");
		exit(-1);
	}
	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName, 65536, 1, DefaultTimeout, errbuf);
	if (adhandle == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(-1);
	}
	/* 查询本机MAC地址 */
	GetDeviceMac(MAC, DeviceName);

	/* 设置过滤器：
	 * 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息(避免误捕获其他客户端发出的多播信息)
	 * 进入循环体前可以重设过滤器，那时再开始接收多播信息 
	 */
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
				MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);

	START_AUTHENTICATION:
	{
		int ret, cnt;
		struct pcap_pkthdr *header;
		const uint8_t *captured;
		uint8_t	ethhdr[14] = {0};	// ethernet frame header
		uint8_t	ip[4] = {0};		// ip address
		
		/* 主动发起认证会话 */
		SendStartPkt(adhandle, MAC);
		/* 等待认证服务器的回应 */
		cnt = 0;
		while (1)
		{
			ret = pcap_next_ex(adhandle, &header, &captured);
			if (ret==1 && (EAP_Code)captured[18]==REQUEST)
				break;
			else
			{
				if(cnt > 50)
				{
					fprintf(stderr, "%s\n", "服务器未响应。");
					exit(-1);
				}
				fprintf(stderr, "%s\n", "等待服务器响应...");
				sleep(1);
				if(GetNetState(DeviceName) == -1)
				{
					fprintf(stderr, "网卡异常！请检查网卡名称是否正确，网线是否插好！\n");
					exit(-1);
				}
				SendStartPkt(adhandle, MAC);
				cnt++;
			}
		}

		/* 填写应答以太帧的报头(以后无须再修改)
		 * 默认以单播方式应答802.1X认证设备发来的Request */
		memcpy(DstMAC+0, captured+6, 6);	//拷贝交换机MAC
		memcpy(ethhdr+0, captured+6, 6);	//拷贝交换机MAC至发包前6位
		memcpy(ethhdr+6, MAC, 6);			//接下来6位为本机MAC
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;
		
		/* 收到的第一个包‘很有‘可能是Notification。取决于校方网络配置 */
		if((EAP_Type)captured[22] == NOTIFICATION)
		{
			printf("[%d]\tServer: Request Notification!\n", captured[19]);
			ResponseNotification(adhandle, captured, ethhdr);
			printf("\tClient: Response Notification.\n");

			/* 继续接收下一个Request包 */
			ret = pcap_next_ex(adhandle, &header, &captured);
			assert(ret==1);
			assert((EAP_Code)captured[18] == REQUEST);
		}
		
		/* 收到的第二个包‘很有‘可能是Identity。取决于校方网络配置 */
		if((EAP_Type)captured[22] == IDENTITY)
		{
			printf("[%d]\tServer: Request Identity!\n", captured[19]);
			GetIpFromDevice(ip, DeviceName);
			ResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
			printf("\tClient: Response Identity.\n");
		}
		else if ((EAP_Type)captured[22] == AVAILIABLE)
		{	// !!!遇到AVAILABLE包时需要特殊处理
			// !!!中南财经政法大学使用的格式：
			// !!!第一个 Request Availiable 要回答 Response Identity
			printf("[%d] Server: Request Availiable first time!\n", captured[19]);
			GetIpFromDevice(ip, DeviceName);
			ResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
			printf("[%d] Client: Response Identity instead.\n", (EAP_ID)captured[19]);
		}

		/* 重设过滤器，只捕获华为802.1X认证设备发来的包
		 *（包括多播Request Identity / Request AVAILABLE
		 */
		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
				captured[6],captured[7],captured[8],captured[9],captured[10],captured[11]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
		pcap_setfilter(adhandle, &fcode);

		/* 进入循环体 */
		LOOP:
		{
			if(GetNetState(DeviceName)==-1)
			{
				fprintf(stderr, "网卡异常！请检查网卡名称是否正确，网线是否插好！\n");
				exit(-1);
			}
			for (;;)
			{
				/* 捕获数据包，直到成功捕获到一个数据包后再跳出*/
				while (pcap_next_ex(adhandle, &header, &captured) != 1)
				{
					sleep(1);
					if(GetNetState(DeviceName) == -1)
					{
						fprintf(stderr, "网卡异常！请检查网卡名称是否正确，网线是否插好！\n");
						exit(-1);
					}
				}
				/* 根据收到的Request，回复相应的Response包 */
				if ((EAP_Code)captured[18] == REQUEST) /* 请求包 */
				{
					fprintf(stdout, "Server: Request [%d]\t", captured[19]);
					switch ((EAP_Type)captured[22])
					{
						case IDENTITY:
							fprintf(stdout, "Identity!");
							GetIpFromDevice(ip, DeviceName);
							ResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
							fprintf(stdout, "\t\t[responsed]\n");
							break;
						case MD5:
							fprintf(stdout, "MD5!");
							ResponseMD5(adhandle, captured, ethhdr, UserName, Password);
							fprintf(stdout, "\t\t[responsed]\n");
							break;
						case NOTIFICATION:
							fprintf(stdout, "Notification!");
							ResponseNotification(adhandle, captured, ethhdr);
							fprintf(stdout, "\t\t[responsed]\n");
							break;
						case AVAILIABLE:
							fprintf(stdout, "Availiable!");
							ResponseAvailiable(adhandle, captured, ethhdr, ip, UserName);
							fprintf(stdout, "\t\t[responsed]\n");
							break;
						default:
							fprintf(stderr, "(type:%d)!\n", (EAP_Type)captured[22]);
							fprintf(stderr, "Error! Unexpected request type\n");
							exit(-1);
							break;
					}
				}
				else if ((EAP_Code)captured[18] == FAILURE) /* 失败包 */
				{
					uint8_t errtype = captured[22];
					uint8_t msgsize = captured[23];
					const char *msg = (const char*) &captured[24];
					printf("[%d] Server: 认证失败。\n", (EAP_ID)captured[19]);
					if (msgsize > 0)
					{
						fprintf(stdout, "%s\n", msg);
						fprintf(stdout, "E2531:用户名不存在\tE2535:Service is paused");
						fprintf(stdout, "E2542:该用户帐号已经在别处登录");
						fprintf(stdout, "E2547:接入时段限制\tE2553:密码错误");
						fprintf(stdout, "E2602:认证会话不存在\tE63100:无效认证客户端版本");
					}
					fprintf(stderr, "errtype = 0x%02x\n", errtype);
					fprintf(stdout, "\n\n重新开始认证......\n");
					goto START_AUTHENTICATION;
				}
				else if ((EAP_Code)captured[18] == SUCCESS) /* 认证成功包 */
				{
					char cmd[30];
					fprintf(stdout, "\n-------认证成功，开始获取IP-------\n");
					strcpy(cmd,"dhclient ");
					strcat(cmd, DeviceName);
					system(cmd);
					fprintf(stdout, "\n-------响应心跳包以保持在线-------\n");
					goto LOOP;
				}
				else if((EAP_Code)captured[18] == H3CDATA) /* H3C数据包 */
				{// TODO: 没有处理华为自定义数据包
					const char *msg = (const char*) &captured[24];
					fprintf(stderr, "[%d] Server: (H3C Data)\n", captured[19]);
					fprintf(stderr, "%s\n", msg);
				}
				else if((EAP_Code)captured[18] == RESPONSE)
				{// TODO: 没有处理华为自定义数据包
					const char *msg = (const char*) &captured[24];
					fprintf(stderr, "[%d] Server: (Response)\n", captured[19]);
					fprintf(stderr, "%s\n", msg);
				}
				else
				{// TODO: 没有处理华为自定义数据包
					const char *msg = (const char*) &captured[24];
					fprintf(stderr, "[%d] Server: (Unknown)\n", captured[19]);
					fprintf(stderr, "%s\n", msg);
				}
			}// forever capture packet
		}//LOOP label
	}//START_AUTHENTICATION label
	return 0;
}

/* 发送EAP-START开始认证包 */
void SendStartPkt(pcap_t *handle, const uint8_t* MAC)
{
	uint8_t packet[18];
	
	memcpy(packet+6, MAC, 6);	//sender's MAC
	packet[12] = 0x88;
	packet[13] = 0x8e;

	/* EAPOL (4 Bytes) */
	packet[14] = 0x01;				// 802.1X Version=1
	packet[15] = 0x01;				// Type=1 Start
	packet[16] = packet[17] =0x00;	// Length=0x0000

	/* 为了兼容不同院校的网络配置，这里发送两遍Start */
	/* 1、广播发送Start包 */
	memcpy(packet, BroadcastAddr, 6);
	pcap_sendpacket(handle, packet, sizeof(packet));
	/* 2、多播发送Start包 */
	memcpy(packet, MulticastAddr, 6);
	pcap_sendpacket(handle, packet, sizeof(packet));	
}

/* 回应Identity类型的请求，返回IP和用户名 */
void ResponseIdentity(pcap_t *adhandle, const uint8_t* request ,
										const uint8_t ethhdr[14],
										const uint8_t ip[4],
										const char* username)
{
	size_t i;
	uint8_t	response[128];
	uint16_t eaplen;
	int usernamelen;
	
	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == IDENTITY);
	
	/* fill ethernet frame header */
	memcpy(response, ethhdr, 14);
	
	response[14] = 0x1;		// 802.1X Version 1
	response[15] = 0x0;		// Type=0 (EAP Packet)
	//response[16~17]留空，Length，最后填
	
	/* Extensible Authentication Protocol */
	response[18] = (EAP_Code) RESPONSE;	// Code
	response[19] = request[19];			// ID
	//response[20~21]留空，Length，最后填

	response[22] = (EAP_Type) IDENTITY;	// Type
	/* Type-Data */
	i = 23;
	response[i++] = 0x15;	  // 上传IP地址
	response[i++] = 0x04;	  //
	memcpy(response+i, ip, 4);//
	i += 4;

	usernamelen = strlen(username); //末尾添加用户名
	memcpy(response+i, username, usernamelen);
	i += usernamelen;
	assert(i <= sizeof(response));

	/* 补填前面留空的两处Length */
	eaplen = htons(i-18);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	while(i<sizeof(response)) {
		response[i]=0x00;
		i++;
	}
	/* 发送 */
	pcap_sendpacket(adhandle, response, i);
	return;
}

/* 生成16字节的MD5信息 */
void FillMD5Area(uint8_t* digest, uint8_t id, 
				 const char* passwd, const uint8_t* srcMD5)
{
	uint8_t	msgbuf[128]; //msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’
	size_t msglen;
	size_t passlen;
	passlen = strlen(passwd);
	msglen = 1 + passlen + 16;
	assert(sizeof(msgbuf) >= msglen);
	msgbuf[0] = id;
	memcpy(msgbuf+1, passwd, passlen);
	memcpy(msgbuf+1+passlen, srcMD5, 16);
	gcry_md_hash_buffer(GCRY_MD_MD5, digest, msgbuf, msglen);
}

/* 回应MD5类型的请求，返回加密后的密码，用户名 */
void ResponseMD5(pcap_t *handle, const uint8_t* request, const uint8_t* ethhdr,
								 const char* username, const char* passwd)
{
	int i;
	uint16_t eaplen;
	size_t usernamelen;
	size_t packetlen;
	uint8_t response[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == MD5);

	usernamelen = strlen(username);
	eaplen = htons(22+usernamelen);
	packetlen = 14+4+22+usernamelen; // ethhdr+EAPOL+EAP+usernamelen

	/* Fill Ethernet frame header */
	memcpy(response, ethhdr, 14);

	/* EAPOL */
	response[14] = 0x1; // 802.1X Version 1
	response[15] = 0x0; // Type=0 (EAP Packet)
	memcpy(response+16, &eaplen, sizeof(eaplen)); // Length

	/* EAP Extensible Authentication Protocol */
	response[18] = (EAP_Code) RESPONSE; // Code
	response[19] = request[19];			// ID
	response[20] = response[16];		// Length
	response[21] = response[17];		// Length
	
	response[22] = (EAP_Type) MD5;		// Type
	response[23] = 16;	// Value-Size: 16 Bytes MD5 data
	FillMD5Area(response+24, request[19], passwd, request+24);
	memcpy(response+40, username, usernamelen); //末尾添加用户名
	i = 40 + usernamelen;
	assert(i <= sizeof(response));
	while(i < sizeof(response)) {
		response[i]=0x00;
		i++;
	}
	/* 发送 */
    pcap_sendpacket(handle, response, packetlen);
}

/* 保持在线，上传客户端版本号及本地IP地址 */
void ResponseAvailiable(pcap_t* handle, const uint8_t* request,
						const uint8_t* ethhdr, const uint8_t ip[4],
						const char* username)
{
	int i, usernamelen;
	uint16_t eaplen;
	uint8_t response[128];
	
	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Code)request[22] == AVAILIABLE);
	
	/* Fill Ethernet frame header */
	memcpy(response, ethhdr, 14);
	
	response[14] = 0x1;		// 802.1X Version 1
	response[15] = 0x0;		// Type=0 (EAP Packet)
	//response[16~17]留空，Length，最后填
	
	response[18] = (EAP_Code) RESPONSE;	// Code
	response[19] = request[19];			// ID
	//response[20~21]留空，Length，最后填
	response[22] = (EAP_Type) AVAILIABLE;// Type
	
	i = 23;
	response[i++] = 0x00;		// 上报是否使用代理
	response[i++] = 0x15;		// 上传IP地址
	response[i++] = 0x04;		//
	memcpy(response+i, ip, 4);	//
	i += 4;
	response[i++] = 0x06;		// 携带版本号
	response[i++] = 0x07;
	FillBase64Area(response+i);
	i += 28;
	response[i++] = ' ';		// 两个空格符
	response[i++] = ' ';		// 
	usernamelen = strlen(username);
	memcpy(response+i, username, usernamelen);
	i += usernamelen;
	
	/* 补填前面留空的两处Length */
	eaplen = htons(i-18);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));
	/* 发送 */
	pcap_sendpacket(handle, response, i);
}

/* 使用密钥key[]对数据data[]进行异或加密
 *（注：该函数也可反向用于解密）*/
void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int i,j;
	/* 正序处理一遍 */
	for (i=0; i<dlen; i++)
		data[i] ^= key[i%klen];
	/* 倒序处理第二遍 */
	for (i=dlen-1,j=0; j<dlen; i--,j++)
		data[i] ^= key[j%klen];
}

/* 生成20字节加密过的Windows版本号信息 */
void FillWindowsVersionArea(uint8_t area[20])
{
	const uint8_t WinVersion[20] = "r70393861";

	memcpy(area, WinVersion, 20);
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

/* 回应Notitfication类型的请求，返回客户端版本和操作系统版本 */
void ResponseNotification(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[])
{
	int i;
	uint8_t	response[67];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == NOTIFICATION);

	/* Fill Ethernet frame header */
	memcpy(response, ethhdr, 14);

	response[14] = 0x1;		// 802.1X Version 1
	response[15] = 0x0;		// Type=0 (EAP Packet)
	response[16] = 0x00;	// Length
	response[17] = 0x31;	// Length

	response[18] = (EAP_Code) RESPONSE;		// Code
	response[19] = (EAP_ID) request[19];	// ID
	response[20] = response[16];			// Length
	response[21] = response[17];			// Length
	response[22] = (EAP_Type) NOTIFICATION;	// Type

	i = 23;
	/* Notification Data (44 Bytes) */
	/* 前2+20字节为客户端版本 */
	response[i++] = 0x01; // type 0x01
	response[i++] = 22;   // length
	FillClientVersionArea(response+i);
	i += 20;

	/* 后2+20字节存储加密后的Windows操作系统版本号 */
	response[i++] = 0x02; // type 0x02
	response[i++] = 22;   // length
	FillWindowsVersionArea(response+i);
	i += 20;
	/* 发送 */
	pcap_sendpacket(handle, response, sizeof(response));
}

/* 发送下线通知 */
void SendLogoffPkt(char *DeviceName)
{
	uint8_t packet[18];
	pcap_t *adhandle; // adapter handle
	const int DefaultTimeout = 60000;//设置接收超时参数，单位ms
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t MAC[6];
	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (adhandle == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		exit(-1);
	}

	GetDeviceMac(MAC, DeviceName);
	/* Ethernet frame Header (14 Bytes) */
	memcpy(packet+0, MulticastAddr, 6); //广播下线
	memcpy(packet+6, MAC, 6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	/* EAPOL (4 Bytes) */
	packet[14] = 0x01;				// Version=1
	packet[15] = 0x02;				// Type=Logoff
	packet[16] = packet[17] = 0x00;	// Length=0x0000
	
	/* 发送 */
	pcap_sendpacket(adhandle, packet, sizeof(packet));
	printf("注销成功。\n");
	exit(0);
}

/* 从MAC地址获取IP */
void GetIpFromDevice(uint8_t ip[4], const char* DeviceName)
{
	int fd;
	struct ifreq ifr;

	assert(strlen(DeviceName) <= IFNAMSIZ);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd>0);

	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
	{
		struct sockaddr_in *p = (void*) &(ifr.ifr_addr);
		memcpy(ip, &(p->sin_addr), 4);
	}
	else
	{
		memset(ip, 0x00, 4);
	}
	close(fd);
}

/* 获取设备的MAC地址 */
void GetDeviceMac(uint8_t mac[6], const char *devicename)
{
	int	sock;
	struct ifreq ifreq;
    sock = socket(AF_INET, SOCK_STREAM, 0);
	strcpy(ifreq.ifr_name, devicename);
    if(ioctl(sock, SIOCGIFHWADDR, &ifreq)==0)
	{
		mac[0]=(uint8_t)ifreq.ifr_hwaddr.sa_data[0];
		mac[1]=(uint8_t)ifreq.ifr_hwaddr.sa_data[1];
		mac[2]=(uint8_t)ifreq.ifr_hwaddr.sa_data[2];
		mac[3]=(uint8_t)ifreq.ifr_hwaddr.sa_data[3];
		mac[4]=(uint8_t)ifreq.ifr_hwaddr.sa_data[4];
		mac[5]=(uint8_t)ifreq.ifr_hwaddr.sa_data[5];
	}
	else
	{
		printf("获取MAC地址失败！\n");
		exit(-1);
	}
	close(sock);
}

/* 获取网络状态：网线是否插好 */
int GetNetState(char *devicename)
{
	char buffer[BUFSIZ];
	FILE *read_fp;
	int chars_read, ret;
	char command[100];
	strcpy(command,"sudo ifconfig ");
	strcat(command, devicename);
	strcat(command," | grep RUNNING");
	memset(buffer, 0, BUFSIZ);

	read_fp = popen(command , "r");
	if(read_fp != NULL)
	{
		chars_read = fread(buffer, sizeof(char), BUFSIZ-1, read_fp);
		if (chars_read > 0)
			ret = 1;
		else
			ret = -1;
		pclose(read_fp);
	}
	else
		ret = -1;
	return ret;
}

/* 生成20字节加密过的H3C版本号信息 */
void FillClientVersionArea(uint8_t area[20])
{
	uint32_t random;
	char RandomKey[8+1];

	random = (uint32_t) time(NULL);    // 注：可以选任意32位整数
	sprintf(RandomKey, "%08x", random);// 生成RandomKey[]字符串

	/* 第一轮异或运算，以RandomKey为密钥加密16字节 */
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	/* 此16字节加上4字节的random，组成总计20字节 */
	random = htonl(random);
	memcpy(area+16, &random, 4);

	/* 第二轮异或运算，以H3C_KEY为密钥加密前面生成的20字节 */
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

/* 按照Base64编码将20字节加密过的H3C版本号信息转换为28字节ASCII字符 */
void FillBase64Area(char area[])
{
	int	i, j;
	uint8_t	c1, c2, c3;
	uint8_t version[20];
	const char* Tbl =	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						"abcdefghijklmnopqrstuvwxyz"
						"0123456789+/"; // 标准的Base64字符映射表

	/* 首先生成20字节加密过的H3C版本号信息 */
	FillClientVersionArea(version);

	/* 按照Base64编码法将前面生成的20字节数据转换为28字节ASCII字符 */
	i = 0;
	j = 0;
	while (j < 24)
	{
		c1 = version[i++];
		c2 = version[i++];
		c3 = version[i++];
		area[j++] = Tbl[ (c1&0xfc)>>2                               ];
		area[j++] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)               ];
		area[j++] = Tbl[               ((c2&0x0f)<<2)|((c3&0xc0)>>6)];
		area[j++] = Tbl[                                c3&0x3f     ];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Tbl[ (c1&0xfc)>>2 ];
	area[25] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
	area[26] = Tbl[               ((c2&0x0f)<<2)];
	area[27] = '=';
}

