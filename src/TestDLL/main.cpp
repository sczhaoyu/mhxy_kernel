#include <windows.h>
#include <iostream>


#include "Kernel/mhxy_kernel.hpp"


typedef struct
{
	int type;   //0�հ���1������2�滻�� ��Ϣ����
	int len;    // ��Ϣ����
	int hwnd;	//��Ϸ���ھ��
	int addr;	//��Ϣ��ַ
} mnj;
void TestMsgCallBack(mnj *msg) {

	char    data[2048];
	memset(data, 0, 2048);
	memcpy(data, (void *)msg->addr, msg->len);

	BytesToHexStr(data, msg->len, data, true);

	std::cout << "��Ϣ:" << msg->len << ":" << msg->type << ":" << msg->addr << ":" << data << std::endl;

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
	//��ʼע��
	//������дDll·��
	char * path = "E:\\�λô���\\mhxy_kernel\\Release\\mhxy_kernel.dll";
	//char * path = "C:\\Users\\ZhaoYu\\Desktop\\mhxy_kernel\\Debug\\mhxy_kernel.dll";
	int addr = DoInjection(path, hwnd, 0);


	
	//����Զ�̺����򿪿���̨
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

	//	////�ֽڱ��
	//	int len = (ret & 0xffff0000) >> 16;
	//	////�ֽ�ֵ
	//	int val = ret & 0x0000ffff;
 //
	//	std::cout << len << ":" << val << std::endl;
	//}

	Sleep(4000000);
	return 0;
}


