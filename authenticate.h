#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <gcrypt.h>
#include <pcap/pcap.h>

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

/* 802.1X报文结构 */
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILIABLE=20} EAP_Type;
typedef uint8_t EAP_ID;

/* 主认证函数 */
int Authentication(char *UserName, char *Password, char *DeviceName);

/* 发送EAP-START开始认证包 */
void SendStartPkt(pcap_t *adhandle, const uint8_t MAC[6]);

/* 回应Identity类型的请求，返回IP和用户名 */
void ResponseIdentity(pcap_t *adhandle, const uint8_t* request,
										const uint8_t ethhdr[14],
										const uint8_t ip[4],
										const char* username);
/* 回应MD5类型的请求，返回加密后的密码，用户名 */
void ResponseMD5(pcap_t *adhandle, const uint8_t* request,
								   const uint8_t ethhdr[14],
								   const char* username,
								   const char* passwd);
/* 回应Notitfication类型的请求，返回客户端版本和操作系统版本 */
void ResponseNotification(pcap_t *handle, const uint8_t* request, 
										  const uint8_t ethhdr[14]);
/* 保持在线，上传客户端版本号及本地IP地址 */
void ResponseAvailiable(pcap_t* handle, const uint8_t* request,
										const uint8_t ethhdr[14],
										const uint8_t ip[4],
										const char* username);
/* 生成20字节加密过的H3C版本号信息 */
void FillClientVersionArea(uint8_t area[20]);
/* 按照Base64编码将20字节加密过的H3C版本号信息转换为28字节ASCII字符 */
void FillBase64Area(uint8_t area[28]);
/* 生成20字节加密过的Windows版本号信息 */
void FillWindowsVersionArea(uint8_t area[20]);
/* 生成16字节的MD5信息 */
void FillMD5Area(uint8_t* digest, uint8_t id,
				 const char* passwd, const uint8_t* srcMD5);

/* 发送下线通知 */
void SendLogoffPkt(char *DeviceName);

/* 获取设备的MAC地址 */
void GetDeviceMac(uint8_t mac[6], const char *DeviceName);
/* 从MAC地址获取IP */
void GetIpFromDevice(uint8_t ip[4], const char* DeviceName);
/* 获取网络状态：网线是否插好 */
int GetNetState(char *devicename);

