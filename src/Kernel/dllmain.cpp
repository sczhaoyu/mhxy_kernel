#include <windows.h>
#include <iostream>
#include<sstream>
#include "mhxy_kernel.hpp"
// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
DWORD HideModule(HMODULE hModule);

bool initDLL(HMODULE hModule) {

	bool ret = true;

	char * className = "WSGAME";
	char name[10];
	char owner[10];

	HWND hwnd = GetWindowHwndByPID(GetCurrentProcessId());
	HWND mh_hwnd = GetWindow(hwnd, GW_OWNER);
	GetClassNameA(hwnd, name, 10);
	GetClassNameA(mh_hwnd, owner, 10);
	//���λ����ξ�ж��ģ��
	if (strcmp(name, className) == 0|| strcmp(owner, className) == 0)
	{
		if (strcmp(owner, className) == 0)
		{
			hwnd = mh_hwnd;
		}
		ret = false;
		//����ģ��
		DWORD newModule = HideModule(hModule);
		stringstream name("mh_");
		name << "mh_";
		name << (int)hwnd;
		//����д�빲����
		LPVOID lpbase = CreateMemoryShare(4096, name.str().c_str());
		FuncAddrs fa;
		//������ַ����
		fa.dllAddr = newModule;
		fa.InitSystemRemoteThread = newModule + ((DWORD)InitSystemRemoteThread - (DWORD)hModule);
		fa.NoticeCallBack = newModule + ((DWORD)NoticeCallBack - (DWORD)hModule);
		fa.RegisterSendPkgRule = newModule + ((DWORD)RegisterSendPkgRule - (DWORD)hModule);
		fa.SetMhMsgCallBack = newModule + ((DWORD)SetMhMsgCallBack - (DWORD)hModule);
		fa.RecvMhxyPkg = newModule + ((DWORD)RecvMhxyPkg - (DWORD)hModule);
		fa.ReplaceSendPkgByte = newModule + ((DWORD)ReplaceSendPkgByte - (DWORD)hModule);
		//�������ڴ湲����
		memcpy(lpbase, &fa, sizeof(FuncAddrs));


	}
	return ret;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	 
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		initDLL(hModule);
		break;
		/*case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			break;*/
	}
	return true;
}

//����ע��ģ��
DWORD HideModule(HMODULE hModule)
{

	//DOS ͷ
	PIMAGE_DOS_HEADER  pDos = (PIMAGE_DOS_HEADER)hModule;
	//NT ͷ
	PIMAGE_NT_HEADERS  pNt = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
	//1.����ռ�
	PBYTE mem = (PBYTE)VirtualAlloc(0, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == mem)
	{
		//����ռ�ʧ��
		return NULL;
	}
	//2.�������µĿռ�
	memcpy(mem, (void*)hModule, pNt->OptionalHeader.SizeOfImage);
	//3.�޸��ض�λ   ����Ŀ¼��6�����ض�λ��
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
	DWORD* item;
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
				item = (DWORD*)(Base + rBase->VirtualAddress + rItem[i].value);
				*item = (*item + offset);
			}
		}

		rBase = (PIMAGE_BASE_RELOCATION)((PBYTE)rBase + rBase->SizeOfBlock);//ָ����һ���ṹ
	}
	return (DWORD)mem;
}