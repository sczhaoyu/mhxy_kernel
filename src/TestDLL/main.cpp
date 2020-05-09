#include <windows.h>
#include <iostream>


#include "Kernel/mhxy_kernel.hpp"


typedef struct
{
	int type;   //0收包，1发包，2替换包 消息类型
	int len;    // 消息长度
	int hwnd;	//游戏窗口句柄
	int addr;	//消息地址
} mnj;
void TestMsgCallBack(mnj *msg) {

	char    data[2048];
	memset(data, 0, 2048);
	memcpy(data, (void *)msg->addr, msg->len);

	BytesToHexStr(data, msg->len, data, true);

	std::cout << "消息:" << msg->len << ":" << msg->type << ":" << msg->addr << ":" << data << std::endl;

}





void openTest(PVOID addr, HANDLE hProcess, char * path) {


	char * title = "funck";

	DWORD BufSize = sizeof(title) + 1;

	LPVOID AllocAddr = VirtualAllocEx(hProcess, NULL, BufSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, AllocAddr, title, BufSize, NULL);

	HANDLE   hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)addr, AllocAddr, 0, NULL);

	Free(hProcess, hRemoteThread, AllocAddr);

}
int main()
{

	HWND  hwnd = FindWindow("WSGAME", 0);
	 //HWND hwnd = FindWindowExA(NULL, NULL, NULL, "TestMFC");
	HANDLE hP = GetThePidOfTargetProcess(hwnd);
	//开始注入
	//这里填写Dll路径
	char * path = "E:\\梦幻代码\\mhxy_kernel\\Release\\mhxy_kernel.dll";
	//char * path = "C:\\Users\\ZhaoYu\\Desktop\\mhxy_kernel\\Debug\\mhxy_kernel.dll";
	int addr = DoInjection(path, hwnd, 0);


	
	//调用远程函数打开控制台
	//PVOID sid = GetHwndDllAddressEx(hwnd, "mhxy_kernel.dll", "OpenConsole");
	//openTest(sid, hP, path);
	//TestCallBack(hP, path);
	Sleep(4000000);
	//callNotice(100,200,300,NULL,8000);



	//InitSystem(path, GetConsoleWindow(), TestMsgCallBack, hwnd);

	//char * a = "WSGAME";
	//char   b[] = "WSGAME";
	//std::cout << strcmp(a, b) << std::endl;


	//unsigned  char  body[] = { 0x80 ,0x09 ,0x0D ,0x05, 0x00 ,0x20, 0x00 ,0x00, 0x00 ,0x00, 0x00 };
	// 

	//for (int i = 0; i < sizeof(body); i++)
	//{
	//	 

	//	int ret = ReplaceSendPkgByte(body[i], sizeof(body),i);

	//	////字节编号
	//	int len = (ret & 0xffff0000) >> 16;
	//	////字节值
	//	int val = ret & 0x0000ffff;
 //
	//	std::cout << len << ":" << val << std::endl;
	//}

	Sleep(4000000);
	return 0;
}


