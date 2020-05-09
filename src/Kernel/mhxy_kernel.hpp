#include <windows.h>
#include <iostream>
#include<sstream>
#include <map>  
#include <string>  
#include <mutex> 
#include <vector>
#include "tlhelp32.h"
#include"TCHAR.H"
#include"Psapi.h"
using namespace std;
typedef struct
{
	int   dllAddr;   //dll基础地址
	int   InitSystemRemoteThread;//远程初始化地址
	int   NoticeCallBack;//设置通知回调地址
	int   RegisterSendPkgRule;	//注册过滤规则			
	int   SetMhMsgCallBack;//设置消息回调				  
	int   RecvMhxyPkg; //收包处理地址
	int   ReplaceSendPkgByte;//发包处理地址
} FuncAddrs;

typedef struct
{
	int head;   // 头编号
	int len;    // 长度
	unsigned  char * body;// 内容
} MapRule;

#pragma pack(1)
typedef struct
{
	int type;   //0收包，1发包，2替换包 消息类型
	int len;    // 消息长度
	char   body[4096];//消息内容
} MhMsg;

typedef struct
{
	HWND hwnd;//当前窗口句柄
	HWND mh_hwnd;//梦幻窗口句柄
	void * callBack;//消息回调函数地址
} ProCallback;

//梦幻消息发送地址
typedef struct
{
	HWND hwnd;   //梦幻句柄
	LPVOID msgAddr;//消息发送地址
} MhSendMsg;
///< 枚举窗口参数
typedef struct
{
	HWND hwndWindow; // 窗口句柄
	DWORD dwProcessID; // 进程ID
}EnumWindowsArg;
///< 枚举窗口回调函数
//创建内存共享区
LPVOID CreateMemoryShare(int size, const char * name);

//获取窗口中dll的函数地址
extern "C" _declspec(dllexport) PVOID GetHwndDllAddressEx(HWND  hwnd, char * dllname, LPCSTR lpProcName);
extern "C" _declspec(dllexport)  BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
extern "C" _declspec(dllexport)  HWND GetWindowHwndByPID(DWORD dwProcessID);
extern "C" _declspec(dllexport)    void    HexReversal(int hex, unsigned char *ret);
//获取进程中的句柄地址
extern "C" _declspec(dllexport) int GetProModuleHandleA(char * dllName, char * funName);
//注入DLL
extern "C" _declspec(dllexport)    int DoInjection(LPCSTR DllPath, HWND  hwnd, HANDLE hProcess);
//获取进程权限
extern "C" _declspec(dllexport)    HANDLE GetThePidOfTargetProcess(HWND hwnd);
extern "C" _declspec(dllexport)    int BytesToHexStr(char* bytes, int len, char * ret, bool space);
extern "C" _declspec(dllexport) void NoticeCallBack(MhMsg * msg);
extern "C" _declspec(dllexport) void Free(HANDLE pro, HANDLE remoteThread, LPVOID allocAddr);
//设置梦幻消息发送地址
void SetMHMsgAddr(MhSendMsg m);
//向梦幻窗口发送消息
extern "C" _declspec(dllexport) BOOL SendMsg(HWND hwnd, char * body, int len);

//=========入参说明==============
//入参：高位放编号
//入参：低位放封包值
//=========返回说明==============
//返回：高位-长度
//返回：低位-放值 
//返回说明：无替换值返回0
extern "C" _declspec(dllexport)  int ReplaceSendPkgByte(int v, int len, int c);
//注册替换封包的内容
//入参1：包头
//入参2：字节内容
//入参3：替换包的长度
extern "C" _declspec(dllexport)  void RegisterSendPkgRule(int head, unsigned char * body, int len);
extern "C" _declspec(dllexport)  void  CloseConsole();
extern "C" _declspec(dllexport)  void  OpenConsole(char * title);
//收包
extern "C" _declspec(dllexport)  int  RecvMhxyPkg(int idx, int len, int addr);
//查找字节
extern "C" _declspec(dllexport)  int  FindBytes(unsigned char * bytes, int bytesLen, unsigned char * findBytes, int findBytesLen, int startIdx);
//替换字节集
extern "C" _declspec(dllexport)  int  ReplaceBytes(unsigned char * bytes, int bytesLen, int start, unsigned char * newBytes, int newBytesLen, unsigned char * ret);
//设置回调函数
extern "C" _declspec(dllexport)  void SetMhMsgCallBack(ProCallback * pc);
/*
初始化梦幻
dllPath 动态库路径
myHwnd    自己的窗口句柄
funcCallBack 自己的回调函数指针地址
mhHwnd//梦幻窗口地址
*/
extern "C" _declspec(dllexport)  int  InitSystem(char * dllPath, int SetMhMsgCallBack, int RecvMhxyPkgAddr, int ReplaceSendPkgByteAddr, HWND myHwnd, void * funcCallBack, HWND mhHwnd);

//远程调用系统初始化
extern "C" _declspec(dllexport)  int  InitSystemRemoteThread(ProCallback *prc);

 