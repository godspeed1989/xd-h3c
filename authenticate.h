#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <gcrypt.h>
#include <pcap.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

const uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const uint8_t MulticastAddr[6] = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址

const char H3C_VERSION[16]	=	"EN V3.60-6303";	// 华为客户端版本号
const char H3C_KEY[]		=	"HuaWei3COM1X";		// H3C的固定密钥

static uint8_t DstMAC[6];	//交换机MAC

/* 自定义报文结构 */
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILIABLE=20} EAP_Type;
typedef uint8_t EAP_ID;

/* 主认证函数 */
int Authentication(char *UserName,char *Password,char *DeviceName);

/* 发送EAP-START开始认证包 */
void SendStartPkt(pcap_t *adhandle, const uint8_t* MAC);
/*  */
void SendLogoffPkt(char *DeviceName);
/* 回应Identity类型的请求 */
void ResponseIdentity(pcap_t *adhandle, const uint8_t* request,
										const uint8_t ethhdr[14],
										const uint8_t ip[4],
										const char* username);
/* 发送加密后的密码 */
void ResponseMD5(pcap_t *adhandle, const uint8_t* request,
								   const uint8_t* ethhdr,
								   const char* username,
								   const char* passwd);
void FillMD5Area(uint8_t* digest, uint8_t id,
				 const char* passwd, const uint8_t* srcMD5);
/* Response client version and OS version */
void ResponseNotification(pcap_t *handle, const uint8_t* request, 
										  const uint8_t* ethhdr);

void ResponseAvailiable(pcap_t* handle, const uint8_t* request,
										const uint8_t* ethhdr,
										const uint8_t ip[4],
										const char* username);
/* 生成20字节加密过的H3C版本号信息 */
void FillClientVersionArea(uint8_t area[20]);
/* 按照Base64编码将20字节加密过的H3C版本号信息转换为28字节ASCII字符 */
void FillBase64Area(char area[28]);
/* 生成20字节加密过的Windows版本号信息 */
void FillWindowsVersionArea(uint8_t area[20]);

/* 发送下线通知 */
void SendLogoffPkt(char *DeviceName);

/* 获取设备的MAC地址 */
void GetDeviceMac(uint8_t mac[6], const char *devicename);
/* 从MAC地址获取IP */
void GetIpFromDevice(uint8_t ip[4], const char* DeviceName);
/* 获取网络状态：网线是否插好 */
int GetNetState(char *devicename);

