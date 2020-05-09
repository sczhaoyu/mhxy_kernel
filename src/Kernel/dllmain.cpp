#include <windows.h>
#include <iostream>
#include<sstream>
#include "mhxy_kernel.hpp"
// dllmain.cpp : 定义 DLL 应用程序的入口点。
DWORD HideModule(HMODULE hModule);
void initDLL(bool ret, HMODULE hModule) {


	HWND hwnd = GetWindowHwndByPID(GetCurrentProcessId());
	char name[10];
	//获取窗口类名
	GetClassNameA(hwnd, name, 10);
	//是梦幻西游就卸载模块
	if (strcmp(name, "WSGAME") == 0)
	{
	 	OpenConsole("mh");
		std::cout << 123 << std::endl; 
		ret = false;
		//隐藏模块
		DWORD newModule = HideModule(hModule);
		stringstream name("mh_");
		name << "mh_";
		name << (int)hwnd;
		//数据写入共享区
		LPVOID lpbase = CreateMemoryShare(4096, name.str().c_str());
		FuncAddrs fa;
		//函数地址设置
		fa.dllAddr = newModule;
		fa.InitSystemRemoteThread = newModule + ((DWORD)InitSystemRemoteThread - (DWORD)hModule);
		fa.NoticeCallBack = newModule + ((DWORD)NoticeCallBack - (DWORD)hModule);
		fa.RegisterSendPkgRule = newModule + ((DWORD)RegisterSendPkgRule - (DWORD)hModule);
		fa.SetMhMsgCallBack = newModule + ((DWORD)SetMhMsgCallBack - (DWORD)hModule);
		fa.RecvMhxyPkg = newModule + ((DWORD)RecvMhxyPkg - (DWORD)hModule);
		fa.ReplaceSendPkgByte = newModule + ((DWORD)ReplaceSendPkgByte - (DWORD)hModule);
		//拷贝到内存共享区
		memcpy(lpbase, &fa, sizeof(FuncAddrs));
		

	}
	 
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	bool ret = true;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		initDLL(ret, hModule);
		break;
		/*case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			break;*/
	}
	return ret;
}

//隐藏注入模块
DWORD HideModule(HMODULE hModule)
{

	//DOS 头
	PIMAGE_DOS_HEADER  pDos = (PIMAGE_DOS_HEADER)hModule;
	//NT 头
	PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
	//1.申请空间
	PBYTE mem = (PBYTE)VirtualAlloc(0, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == mem)
	{
		//申请空间失败
		return NULL;
	}
	//2.拷贝到新的空间
	memcpy(mem, (void *)hModule, pNt->OptionalHeader.SizeOfImage);
	//3.修复重定位   数据目录第6项是重定位表
	PIMAGE_BASE_RELOCATION  rBase = (PIMAGE_BASE_RELOCATION)((DWORD)mem + pNt->OptionalHeader.DataDirectory[5].VirtualAddress);
	DWORD n = 0;
	DWORD Base = (DWORD)mem;
	DWORD offset = (DWORD)mem - (DWORD)hModule;
	if (offset == 0)
		(DWORD)mem;

	typedef struct RELOCATIONITEM
	{
		WORD value : 12;
		WORD attr : 4;

	} *PRELOCATIONITEM;
	PRELOCATIONITEM   rItem;
	DWORD *item;
	while (true)
	{
		if (rBase->SizeOfBlock == 0)
			break;
		rItem = (PRELOCATIONITEM)((PBYTE)rBase + 8);
		n = (rBase->SizeOfBlock - 8) / 2;
		for (unsigned int i = 0; i < n; ++i)
		{
			if (3 == rItem[i].attr)
			{
				item = (DWORD *)(Base + rBase->VirtualAddress + rItem[i].value);
				*item = (*item + offset);
			}
		}

		rBase = (PIMAGE_BASE_RELOCATION)((PBYTE)rBase + rBase->SizeOfBlock);//指向下一个结构
	}
	return (DWORD)mem;
}