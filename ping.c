#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")

typedef struct {
  union {
    struct {
      u_char s_b1,s_b2,s_b3,s_b4;
    } S_un_b;
    struct {
      u_short s_w1,s_w2;
    } S_un_w;
    u_long S_addr;
  } S_un;
} IPAddr;

typedef struct ip_option_information {
  UCHAR  Ttl;
  UCHAR  Tos;
  UCHAR  Flags;
  UCHAR  OptionsSize;
  PUCHAR OptionsData;
} IP_OPTION_INFORMATION, *PIP_OPTION_INFORMATION;
typedef struct _IO_STATUS_BLOCK {
  union {
    //NTSTATUS Status;
	  DWORD Status;
    PVOID    Pointer;
  };
  //ULONG_PTR Information;
  unsigned long * Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (WINAPI*PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
);


typedef HANDLE (* _IcmpCreateFile)(void);
#define _In_
#define _Out_
#define _In_opt_
typedef  DWORD  (WINAPI* _IcmpSendEcho)(
  _In_     HANDLE                 IcmpHandle,
  _In_     IPAddr                 DestinationAddress,
  _In_     LPVOID                 RequestData,
  _In_     WORD                   RequestSize,
  _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
  _Out_    LPVOID                 ReplyBuffer,
  _In_     DWORD                  ReplySize,
  _In_     DWORD                  Timeout
);
typedef BOOL (WINAPI*_IcmpCloseHandle)(
  _In_ HANDLE IcmpHandle
);



typedef DWORD (WINAPI*  _IcmpSendEcho2)(
  _In_     HANDLE                 IcmpHandle,
  _In_opt_ HANDLE                 Event,
  _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
  _In_opt_ PVOID                  ApcContext,
  _In_     DWORD                  DestinationAddress,
  _In_     LPVOID                 RequestData,
  _In_     WORD                   RequestSize,
  _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
  _Out_    LPVOID                 ReplyBuffer,
  _In_     DWORD                  ReplySize,
  _In_     DWORD                  Timeout
);

typedef struct icmp_echo_reply {
  IPAddr                       Address;
  ULONG                        Status;
  ULONG                        RoundTripTime;
  USHORT                       DataSize;
  USHORT                       Reserved;
  PVOID                        Data;
  struct ip_option_information  Options;
} ICMP_ECHO_REPLY, *PICMP_ECHO_REPLY;

#define IP_DEST_HOST_UNREACHABLE 11003
#define IP_REQ_TIMED_OUT 11010
#define IP_BUF_TOO_SMALL 11001
#define IP_DEST_NET_UNREACHABLE 11002
BOOL SendPingByIp(char * sIP)
{
	HANDLE hIcmpFile;
	//unsigned long ipaddr = INADDR_NONE;
	IPAddr ipaddr = {0};
	DWORD dwRetVal = 0;
	char SendData[] = "Hello world";
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;

	HMODULE hIphlpapi = LoadLibraryA("c:\\windows\\syswow64\\icmp.dll");
	_IcmpSendEcho IcmpSendEcho = (_IcmpSendEcho)GetProcAddress(hIphlpapi,"IcmpSendEcho");
	_IcmpCreateFile IcmpCreateFile = (_IcmpCreateFile)GetProcAddress(hIphlpapi,"IcmpCreateFile");
	_IcmpCloseHandle IcmpCloseHandle = (_IcmpCloseHandle)GetProcAddress(hIphlpapi,"IcmpCloseHandle");
	printf("%p %p",IcmpSendEcho,IcmpCreateFile);

	ipaddr.S_un.S_addr = inet_addr(sIP);

	if (ipaddr.S_un.S_addr == INADDR_NONE)
	return FALSE;

	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}   

	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	ReplyBuffer = (VOID*) malloc(ReplySize);
	memset(ReplyBuffer,0,ReplySize);
	if (ReplyBuffer == NULL) {
		CloseHandle(hIcmpFile);
		return FALSE;
	}   


	dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),  
	NULL, ReplyBuffer, ReplySize, 6000);
	if (dwRetVal == 0)
	{
		free(ReplyBuffer);
		CloseHandle(hIcmpFile);
		return FALSE;
	}

	free(ReplyBuffer);
	CloseHandle(hIcmpFile);
	return TRUE;
}

int main() {

	HANDLE hIcmpFile;
    unsigned long ipaddr = INADDR_NONE;
    DWORD dwRetVal = 0;
    DWORD dwError = 0;
    char SendData[] = "Data Buffer";
    LPVOID ReplyBuffer = NULL;
    DWORD ReplySize = 0;

	HMODULE hIphlpapi = LoadLibraryA("c:\\windows\\syswow64\\icmp.dll");
	_IcmpCreateFile IcmpCreateFile = (_IcmpCreateFile)GetProcAddress(hIphlpapi,"IcmpCreateFile");
	_IcmpSendEcho2 IcmpSendEcho2 = (_IcmpSendEcho2)GetProcAddress(hIphlpapi,"IcmpSendEcho2");
	printf("%p %p",IcmpSendEcho2,IcmpCreateFile);

    ipaddr = inet_addr("118.184.53.36");

    hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("\tUnable to open handle.\n");
        printf("IcmpCreatefile returned error: %ld\n", GetLastError());
        return -1;
    }
    // Allocate space for at a single reply
    ReplySize = sizeof (ICMP_ECHO_REPLY) + sizeof (SendData) + 8;
    ReplyBuffer = (VOID *) malloc(ReplySize);
    if (ReplyBuffer == NULL) {
        printf("\tUnable to allocate memory for reply buffer\n");
        return -1;
    }

    dwRetVal = IcmpSendEcho2(hIcmpFile, NULL, NULL, NULL,
                             ipaddr, SendData, sizeof (SendData), NULL,
                             ReplyBuffer, ReplySize, 1000);
    if (dwRetVal != 0) {
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY) ReplyBuffer;
        struct in_addr ReplyAddr;
        ReplyAddr.S_un.S_addr = pEchoReply->Address.S_un.S_addr;
        printf("\tSent icmp message to %s\n", "...");
        if (dwRetVal > 1) {
            printf("\tReceived %ld icmp message responses\n", dwRetVal);
            printf("\tInformation from the first response:%s\n",pEchoReply->Data);
        } else {
			
            printf("\tReceived %ld icmp message response\n", dwRetVal);
            printf("\tInformation from this response:%s\n",pEchoReply->Data);
        }
        printf("\t  Received from %s\n", inet_ntoa(ReplyAddr));
        printf("\t  Status = %ld  ", pEchoReply->Status);
        switch (pEchoReply->Status) {
        case IP_DEST_HOST_UNREACHABLE:
            printf("(Destination host was unreachable)\n");
            break;
        case IP_DEST_NET_UNREACHABLE:
            printf("(Destination Network was unreachable)\n");
            break;
        case IP_REQ_TIMED_OUT:
            printf("(Request timed out)\n");
            break;
        default:
            printf("\n");
            break;
        }

        printf("\t  Roundtrip time = %ld milliseconds\n",
               pEchoReply->RoundTripTime);
    } else {
        printf("Call to IcmpSendEcho2 failed.\n");
        dwError = GetLastError();
        switch (dwError) {
        case IP_BUF_TOO_SMALL:
            printf("\tReplyBufferSize to small\n");
            break;
        case IP_REQ_TIMED_OUT:
            printf("\tRequest timed out\n");
            break;
        default:
            printf("\tExtended error returned: %ld\n", dwError);
            break;
        }
        return -1;
    }
    return 0;
}

