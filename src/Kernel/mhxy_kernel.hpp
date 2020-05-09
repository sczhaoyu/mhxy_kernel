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
	int   dllAddr;   //dll������ַ
	int   InitSystemRemoteThread;//Զ�̳�ʼ����ַ
	int   NoticeCallBack;//����֪ͨ�ص���ַ
	int   RegisterSendPkgRule;	//ע����˹���			
	int   SetMhMsgCallBack;//������Ϣ�ص�				  
	int   RecvMhxyPkg; //�հ������ַ
	int   ReplaceSendPkgByte;//���������ַ
} FuncAddrs;

typedef struct
{
	int head;   // ͷ���
	int len;    // ����
	unsigned  char * body;// ����
} MapRule;

#pragma pack(1)
typedef struct
{
	int type;   //0�հ���1������2�滻�� ��Ϣ����
	int len;    // ��Ϣ����
	char   body[4096];//��Ϣ����
} MhMsg;

typedef struct
{
	HWND hwnd;//��ǰ���ھ��
	HWND mh_hwnd;//�λô��ھ��
	void * callBack;//��Ϣ�ص�������ַ
} ProCallback;

//�λ���Ϣ���͵�ַ
typedef struct
{
	HWND hwnd;   //�λþ��
	LPVOID msgAddr;//��Ϣ���͵�ַ
} MhSendMsg;
///< ö�ٴ��ڲ���
typedef struct
{
	HWND hwndWindow; // ���ھ��
	DWORD dwProcessID; // ����ID
}EnumWindowsArg;
///< ö�ٴ��ڻص�����
//�����ڴ湲����
LPVOID CreateMemoryShare(int size, const char * name);

//��ȡ������dll�ĺ�����ַ
extern "C" _declspec(dllexport) PVOID GetHwndDllAddressEx(HWND  hwnd, char * dllname, LPCSTR lpProcName);
extern "C" _declspec(dllexport)  BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
extern "C" _declspec(dllexport)  HWND GetWindowHwndByPID(DWORD dwProcessID);
extern "C" _declspec(dllexport)    void    HexReversal(int hex, unsigned char *ret);
//��ȡ�����еľ����ַ
extern "C" _declspec(dllexport) int GetProModuleHandleA(char * dllName, char * funName);
//ע��DLL
extern "C" _declspec(dllexport)    int DoInjection(LPCSTR DllPath, HWND  hwnd, HANDLE hProcess);
//��ȡ����Ȩ��
extern "C" _declspec(dllexport)    HANDLE GetThePidOfTargetProcess(HWND hwnd);
extern "C" _declspec(dllexport)    int BytesToHexStr(char* bytes, int len, char * ret, bool space);
extern "C" _declspec(dllexport) void NoticeCallBack(MhMsg * msg);
extern "C" _declspec(dllexport) void Free(HANDLE pro, HANDLE remoteThread, LPVOID allocAddr);
//�����λ���Ϣ���͵�ַ
void SetMHMsgAddr(MhSendMsg m);
//���λô��ڷ�����Ϣ
extern "C" _declspec(dllexport) BOOL SendMsg(HWND hwnd, char * body, int len);

//=========���˵��==============
//��Σ���λ�ű��
//��Σ���λ�ŷ��ֵ
//=========����˵��==============
//���أ���λ-����
//���أ���λ-��ֵ 
//����˵�������滻ֵ����0
extern "C" _declspec(dllexport)  int ReplaceSendPkgByte(int v, int len, int c);
//ע���滻���������
//���1����ͷ
//���2���ֽ�����
//���3���滻���ĳ���
extern "C" _declspec(dllexport)  void RegisterSendPkgRule(int head, unsigned char * body, int len);
extern "C" _declspec(dllexport)  void  CloseConsole();
extern "C" _declspec(dllexport)  void  OpenConsole(char * title);
//�հ�
extern "C" _declspec(dllexport)  int  RecvMhxyPkg(int idx, int len, int addr);
//�����ֽ�
extern "C" _declspec(dllexport)  int  FindBytes(unsigned char * bytes, int bytesLen, unsigned char * findBytes, int findBytesLen, int startIdx);
//�滻�ֽڼ�
extern "C" _declspec(dllexport)  int  ReplaceBytes(unsigned char * bytes, int bytesLen, int start, unsigned char * newBytes, int newBytesLen, unsigned char * ret);
//���ûص�����
extern "C" _declspec(dllexport)  void SetMhMsgCallBack(ProCallback * pc);
/*
��ʼ���λ�
dllPath ��̬��·��
myHwnd    �Լ��Ĵ��ھ��
funcCallBack �Լ��Ļص�����ָ���ַ
mhHwnd//�λô��ڵ�ַ
*/
extern "C" _declspec(dllexport)  int  InitSystem(char * dllPath, int SetMhMsgCallBack, int RecvMhxyPkgAddr, int ReplaceSendPkgByteAddr, HWND myHwnd, void * funcCallBack, HWND mhHwnd);

//Զ�̵���ϵͳ��ʼ��
extern "C" _declspec(dllexport)  int  InitSystemRemoteThread(ProCallback *prc);

 