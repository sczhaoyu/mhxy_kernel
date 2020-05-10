#include "mhxy_kernel.hpp"
MapRule   rules[255];
ProCallback* MsgCallBack = 0;//消息回调函数
int msgRecvAddr = 0;//消息回复地址
MhSendMsg sendMsgAddr[32];//梦幻消息发送地址
void console(char* title) {
	//打开控制台窗口以显示调试信息
	AllocConsole();
	//设置标题
	SetConsoleTitleA(title);
	//重定向输出
	freopen("CONOUT$", "w+t", stdout);
}
void  OpenConsole(char* title) {
	if (title == 0 || title == nullptr)
	{
		title = "调试信息";
	}
	console(title);

}
string bytestohexstring(char* bytes, int bytelength, bool space)
{
	string str("");
	string str2("0123456789ABCDEF");
	for (int i = 0; i < bytelength; i++) {
		int b;
		b = 0x0f & (bytes[i] >> 4);
		char s1 = str2.at(b);
		str.append(1, str2.at(b));
		b = 0x0f & bytes[i];
		str.append(1, str2.at(b));
		char s2 = str2.at(b);
		if (bytelength - 1 != i && space == true)
		{
			str.append(" ");
		}
	}
	return str;
}
int RecvMhxyPkg(int idx, int len, int addr)
{
	
	if (idx == len)
	{
		
		static MhMsg msg;
		 
		memcpy(msg.body, (void*)addr, len+1);
		msg.len = len + 1;
		msg.type = 0;
		NoticeCallBack(&msg);

	}

	return 0;
}
int FindBytes(unsigned char* bytes, int bytesLen, unsigned char* findBytes, int findBytesLen, int startIdx)
{
	for (int k = startIdx; k < bytesLen; k++)
	{
		bool ret = true;
		for (int i = 0; i < findBytesLen; i++)
		{
			if (bytes[k + i] != findBytes[i])
			{
				ret = false;
			}
		}
		if (ret)
		{
			return k;
		}
	}

	return -1;
}

int ReplaceBytes(unsigned char* bytes, int bytesLen, int start, unsigned char* newBytes, int newBytesLen, unsigned char* ret)
{
	//获取前半段数据
	char* prev = new    char[start];
	memcpy(prev, bytes, start);
	//获取后半段数据
	int lastLen = bytesLen - (start + newBytesLen);
	char* last = new   char[lastLen];
	memcpy(last, bytes + start + newBytesLen, lastLen);

	//链接数据
	int allLen = newBytesLen + start + lastLen;

	memcpy(ret, prev, start);
	memcpy(ret + start, newBytes, newBytesLen);
	memcpy(ret + start + newBytesLen, last, lastLen);
	delete prev;
	delete last;
	return allLen;
}

void SetMhMsgCallBack(ProCallback* pc)
{
	OpenConsole("日志信息");
	if (MsgCallBack!=nullptr)
	{
		delete MsgCallBack;
	}
	MsgCallBack = new ProCallback;
	MsgCallBack->callBack = pc->callBack;
	MsgCallBack->hwnd = pc->hwnd;
	MsgCallBack->mh_hwnd = pc->mh_hwnd;
	//初始化系统
	msgRecvAddr = 0;

}
int InitSystem(char* dllPath, int SetMhMsgCallBack, int RecvMhxyPkgAddr, int ReplaceSendPkgByteAddr, HWND myHwnd, void* funcCallBack, HWND mhHwnd)
{


	//获取进程
	HANDLE pro = GetThePidOfTargetProcess(mhHwnd);
	//申请内存
	LPVOID addr = VirtualAllocEx(pro, 0, 4096, MEM_COMMIT, 64);

	ProCallback prc;
	prc.callBack = funcCallBack;
	prc.hwnd = myHwnd;
	prc.mh_hwnd = mhHwnd;
	//设置回调函数
	LPVOID AllocAddr = VirtualAllocEx(pro, NULL, sizeof(ProCallback), MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(pro, AllocAddr, &prc, sizeof(ProCallback), NULL);


	HANDLE   hRemoteThread = CreateRemoteThread(pro, NULL, 0, (PTHREAD_START_ROUTINE)SetMhMsgCallBack, AllocAddr, 0, NULL);
	// 等待远线程结束
	WaitForSingleObject(hRemoteThread, INFINITE);
	Free(0, hRemoteThread, AllocAddr);



	unsigned char code[] = { 136,12,16,93,131,248,2,115,3,194,12,0,96,82,102,139,90,1,15,183,219,131,195,2,83,80,187,144,34,6,99,255,211,131,196,12,97,194,12,0 };
	//旧地址
	unsigned char dllModule[] = { 144,34,6,99 };
	int idx = FindBytes(code, sizeof(code), dllModule, 4, 0);



	//模块地址转16进制
	unsigned char   newDllModule[4];
	HexReversal(RecvMhxyPkgAddr, newDllModule);

	unsigned char* newCode = new unsigned char[2048];
	memset(newCode, 0, 2048);
	//替换模块的旧地址
	int len = ReplaceBytes(code, sizeof(code), idx, newDllModule, sizeof(newDllModule), newCode);

	LPVOID codeAddr = (LPVOID)((int)addr + 1024);
	//写入收包代码
	WriteProcessMemory(pro, codeAddr, newCode, 2048, NULL);
	//搜索基址
	int mhCodeLen = 7245824;//大小
	int moudleStart = 286000000;//模块起始地址
	unsigned char* mhCodes = new  unsigned char[mhCodeLen];
	memset(mhCodes, 0, mhCodeLen);
	ReadProcessMemory(pro, (LPCVOID)moudleStart, mhCodes, mhCodeLen, 0);
	unsigned char recvPkg[] = { 139,18,139,69,8,138,77,16 };// { 139, 68, 36, 4, 138, 76, 36, 12 };
	//查找收包特征码
	idx = FindBytes(mhCodes, mhCodeLen, recvPkg, sizeof(recvPkg), 0);
	//处理跳转的代码地址
	int jmp = moudleStart + idx+8;
	newDllModule[4];
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned char jmpBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//写入收包跳转
	WriteProcessMemory(pro, (LPVOID)jmp, jmpBytes, sizeof(jmpBytes), NULL);
	//修改写入地址
	codeAddr = (LPVOID)((int)codeAddr + len);

	//重置数据
	memset(newCode, 0, 2048);
	unsigned char sendCode[] = { 141,95,16,131,127,20,16,15,130,4,0,0,0,139,63,117,0,15,190,4,58,15,182,201,95,49,200,60,241,15,132,18,0,0,0,128,61,0,0,183,7,0,15,133,29,0,0,0,233,69,0,0,0,185,1,0,0,0,136,13,0,0,183,7,139,13,1,0,183,7,137,11,233,0,0,0,0,15,182,130,5,0,183,7,53,0,255,255,255,96,139,3,131,232,1,187,0,0,0,0,185,1,0,0,0,57,194,15,68,203,136,13,0,0,183,7,97,233,0,0,0,0,96,37,255,0,0,0,82,255,51,80,187,96,36,4,99,255,211,137,68,36,36,131,196,12,97,233,0,0,0,0,131,124,36,248,0,117,5,233,30,0,0,0,139,68,36,248,37,0,0,255,255,193,232,16,137,3,139,68,36,248,37,255,255,0,0,53,0,255,255,255,117,0,91,89,194,8,0 };
	//新的发包地址
	unsigned char   sendAddr[4];
	HexReversal((int)addr, sendAddr);
	//旧的发包地址
	unsigned char oldSendAddr[4] = { 0x00,0x00,0xB7,0x07 };
	//第一处
	idx = FindBytes(sendCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(sendCode, sizeof(sendCode), idx, sendAddr, sizeof(sendAddr), newCode);

	//第二处
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);

	//第三处
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);


	//标记位置
	unsigned char oldSendAddrFlag[4] = { 0x01,0x00,0xB7,0x07 };
	unsigned char   sendAddrFlag[4];
	HexReversal((int)addr + 1, sendAddrFlag);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrFlag, sizeof(oldSendAddrFlag), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrFlag, sizeof(sendAddrFlag), newCode);

	//长度位置
	unsigned char oldSendAddrLen[4] = { 0x05,0x00,0xB7,0x07 };
	unsigned char   sendAddrLen[4];
	HexReversal((int)addr + 5, sendAddrLen);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrLen, sizeof(oldSendAddrLen), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrLen, sizeof(sendAddrLen), newCode);




	//替换发包地址
	unsigned char oldSendCall[4] = { 0x60, 0x24, 0x04 ,0x63 };
	unsigned char   sendCall[4];
	HexReversal(ReplaceSendPkgByteAddr, sendCall);
	idx = FindBytes(newCode, mhCodeLen, oldSendCall, sizeof(oldSendCall), 0);
	len = ReplaceBytes(newCode, len, idx, sendCall, sizeof(sendCall), newCode);
	//写入发包代码
	WriteProcessMemory(pro, codeAddr, newCode, len, NULL);

	//处理发包跳转
	unsigned char sendPkg[] = { 126, 8, 138, 194, 179, 53, 246, 235 };
	//查找发包特征码
	idx = FindBytes(mhCodes, mhCodeLen, sendPkg, sizeof(sendPkg), 0);

	//处理跳转的代码地址
	jmp = moudleStart + idx + 13;
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned	char jmpSendBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//写入收包跳转
	WriteProcessMemory(pro, (LPVOID)jmp, jmpSendBytes, sizeof(jmpSendBytes), NULL);



	CloseHandle(pro);
	delete mhCodes;
	msgRecvAddr = 0;//重置系统标志

	MhSendMsg mm;
	mm.hwnd = mhHwnd;
	mm.msgAddr = addr;

	SetMHMsgAddr(mm);//保存消息发送地址
	return (int)addr;
}

int InitSystemRemoteThread(ProCallback* prc)
{
	//获取进程
	HANDLE pro = GetCurrentProcess();
	//申请内存
	LPVOID addr = VirtualAllocEx(pro, 0, 4096, MEM_COMMIT, 64);
	//设置回调函数
	SetMhMsgCallBack(prc);
	unsigned char code[] = { 136,12,16,131,248,2,15,131,3,0,0,0,194,12,0,96,82,102,139,90,1,15,183,219,131,195,2,83,80,187,144,34,6,99,255,211,131,196,12,97,194,12,0 };
	//旧地址
	unsigned char dllModule[] = { 144,34,6,99 };
	int idx = FindBytes(code, sizeof(code), dllModule, 4, 0);

	//模块地址转16进制
	unsigned char   newDllModule[4];
	HexReversal((int)RecvMhxyPkg, newDllModule);

	unsigned char* newCode = new unsigned char[2048];
	memset(newCode, 0, 2048);
	//替换模块的旧地址
	int len = ReplaceBytes(code, sizeof(code), idx, newDllModule, sizeof(newDllModule), newCode);

	LPVOID codeAddr = (LPVOID)((int)addr + 1024);
	//写入收包代码
	WriteProcessMemory(pro, codeAddr, newCode, 2048, NULL);
	//搜索基址
	int mhCodeLen = 7245824;//大小
	int moudleStart = 286261248;//模块起始地址
	unsigned char* mhCodes = new  unsigned char[mhCodeLen];
	memset(mhCodes, 0, mhCodeLen);
	ReadProcessMemory(pro, (LPCVOID)moudleStart, mhCodes, mhCodeLen, 0);
	unsigned char recvPkg[] = { 139, 68, 36, 4, 138, 76, 36, 12 };
	//查找收包特征码
	idx = FindBytes(mhCodes, mhCodeLen, recvPkg, sizeof(recvPkg), 0);
	//处理跳转的代码地址
	int jmp = moudleStart + idx + 8;
	newDllModule[4];
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned char jmpBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//写入收包跳转
	WriteProcessMemory(pro, (LPVOID)jmp, jmpBytes, sizeof(jmpBytes), NULL);
	//修改写入地址
	codeAddr = (LPVOID)((int)codeAddr + len);

	//重置数据
	memset(newCode, 0, 2048);
	unsigned char sendCode[] = { 141,95,16,131,127,20,16,15,130,4,0,0,0,139,63,117,0,15,190,4,58,15,182,201,95,49,200,60,241,15,132,18,0,0,0,128,61,0,0,183,7,0,15,133,29,0,0,0,233,69,0,0,0,185,1,0,0,0,136,13,0,0,183,7,139,13,1,0,183,7,137,11,233,0,0,0,0,15,182,130,5,0,183,7,53,0,255,255,255,96,139,3,131,232,1,187,0,0,0,0,185,1,0,0,0,57,194,15,68,203,136,13,0,0,183,7,97,233,0,0,0,0,96,37,255,0,0,0,82,255,51,80,187,96,36,4,99,255,211,137,68,36,36,131,196,12,97,233,0,0,0,0,131,124,36,248,0,117,5,233,30,0,0,0,139,68,36,248,37,0,0,255,255,193,232,16,137,3,139,68,36,248,37,255,255,0,0,53,0,255,255,255,117,0,91,89,194,8,0 };
	//新的发包地址
	unsigned char   sendAddr[4];
	HexReversal((int)addr, sendAddr);
	//旧的发包地址
	unsigned char oldSendAddr[4] = { 0x00,0x00,0xB7,0x07 };
	//第一处
	idx = FindBytes(sendCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(sendCode, sizeof(sendCode), idx, sendAddr, sizeof(sendAddr), newCode);

	//第二处
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);

	//第三处
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);


	//标记位置
	unsigned char oldSendAddrFlag[4] = { 0x01,0x00,0xB7,0x07 };
	unsigned char   sendAddrFlag[4];
	HexReversal((int)addr + 1, sendAddrFlag);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrFlag, sizeof(oldSendAddrFlag), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrFlag, sizeof(sendAddrFlag), newCode);

	//长度位置
	unsigned char oldSendAddrLen[4] = { 0x05,0x00,0xB7,0x07 };
	unsigned char   sendAddrLen[4];
	HexReversal((int)addr + 5, sendAddrLen);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrLen, sizeof(oldSendAddrLen), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrLen, sizeof(sendAddrLen), newCode);




	//替换发包地址
	unsigned char oldSendCall[4] = { 0x60, 0x24, 0x04 ,0x63 };
	unsigned char   sendCall[4];
	HexReversal((int)ReplaceSendPkgByte, sendCall);
	idx = FindBytes(newCode, mhCodeLen, oldSendCall, sizeof(oldSendCall), 0);
	len = ReplaceBytes(newCode, len, idx, sendCall, sizeof(sendCall), newCode);
	//写入发包代码
	WriteProcessMemory(pro, codeAddr, newCode, len, NULL);

	//处理发包跳转
	unsigned char sendPkg[] = { 126, 8, 138, 194, 179, 53, 246, 235 };
	//查找发包特征码
	idx = FindBytes(mhCodes, mhCodeLen, sendPkg, sizeof(sendPkg), 0);

	//处理跳转的代码地址
	jmp = moudleStart + idx + 13;
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned	char jmpSendBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//写入收包跳转
	WriteProcessMemory(pro, (LPVOID)jmp, jmpSendBytes, sizeof(jmpSendBytes), NULL);

	delete mhCodes;
	msgRecvAddr = 0;//重置系统标志
	return (int)addr;
}

//释放控制台
void  CloseConsole() {
	FreeConsole();
}
typedef struct EnumHWndsArg
{
	std::vector<HWND>* vecHWnds;
	DWORD dwProcessId;
}EnumHWndsArg, * LPEnumHWndsArg;

BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam)
{
	EnumHWndsArg* pArg = (LPEnumHWndsArg)lParam;
	DWORD  processId;
	GetWindowThreadProcessId(hwnd, &processId);
	if (processId == pArg->dwProcessId)
	{
		pArg->vecHWnds->push_back(hwnd);
		//printf("%p\n", hwnd);
	}
	return TRUE;
}

void GetHWndsByProcessID(DWORD processID, std::vector<HWND>& vecHWnds)
{
	EnumHWndsArg wi;
	wi.dwProcessId = processID;
	wi.vecHWnds = &vecHWnds;
	EnumWindows(lpEnumFunc, (LPARAM)&wi);

}
bool  GetModule(DWORD process, char* dllname, MODULEENTRY32& me32)
{
	//获取远程进程的模块快照
	HANDLE module_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process);
	if (INVALID_HANDLE_VALUE == module_handle)
	{

		return false;
	}
	//遍历模块，找到指定模块
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(module_handle, &me32))
	{
		CloseHandle(module_handle);

		return false;
	}
	bool is_found = false;
	do
	{
		is_found = (_tcsicmp(me32.szModule, dllname) == 0 || _tcsicmp(me32.szExePath, dllname) == 0);
		if (is_found)
		{
			break;
		}
	} while (Module32Next(module_handle, &me32));
	//返回查找结果
	return is_found;
}
//跨进程取函数地址
PVOID GetProcAddressEx(HANDLE hProc, HMODULE hModule, LPCSTR lpProcName)
{
	PVOID pAddress = NULL;
	SIZE_T OptSize;
	IMAGE_DOS_HEADER DosHeader;
	SIZE_T ProcNameLength = lstrlenA(lpProcName) + sizeof(CHAR);//'\0'

																//读DOS头
	if (ReadProcessMemory(hProc, hModule, &DosHeader, sizeof(DosHeader), &OptSize))
	{
		IMAGE_NT_HEADERS NtHeader;

		//读NT头
		if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + DosHeader.e_lfanew), &NtHeader, sizeof(NtHeader), &OptSize))
		{
			IMAGE_EXPORT_DIRECTORY ExpDir;
			SIZE_T ExportVirtualAddress = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

			//读输出表
			if (ExportVirtualAddress && ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExportVirtualAddress), &ExpDir, sizeof(ExpDir), &OptSize))
			{
				if (ExpDir.NumberOfFunctions)
				{
					//x64待定:地址数组存放RVA的数据类型是4字节还是8字节???
					SIZE_T* pProcAddressTable = (SIZE_T*)GlobalAlloc(GPTR, ExpDir.NumberOfFunctions * sizeof(SIZE_T));

					//读函数地址表
					if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfFunctions), pProcAddressTable, ExpDir.NumberOfFunctions * sizeof(PVOID), &OptSize))
					{
						//x64待定:名称数组存放RVA的数据类型是4字节还是8字节???
						SIZE_T* pProcNamesTable = (SIZE_T*)GlobalAlloc(GPTR, ExpDir.NumberOfNames * sizeof(SIZE_T));

						//读函数名称表
						if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfNames), pProcNamesTable, ExpDir.NumberOfNames * sizeof(PVOID), &OptSize))
						{
							CHAR* pProcName = (CHAR*)GlobalAlloc(GPTR, ProcNameLength);

							//遍历函数名称
							for (DWORD i = 0; i < ExpDir.NumberOfNames; i++)
							{
								if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + pProcNamesTable[i]), pProcName, ProcNameLength, &OptSize))
								{
									if (RtlEqualMemory(lpProcName, pProcName, ProcNameLength))
									{
										//x64待定:函数在地址数组索引的数据类型是2字节还是???
										WORD NameOrdinal;

										//获取函数在地址表的索引
										if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfNameOrdinals + sizeof(NameOrdinal) * i), &NameOrdinal, sizeof(NameOrdinal), &OptSize))
										{
											pAddress = (PVOID)((SIZE_T)hModule + pProcAddressTable[NameOrdinal]);
										}
										break;//for
									}
								}
							}
							GlobalFree(pProcName);
						}
						GlobalFree(pProcNamesTable);
					}
					GlobalFree(pProcAddressTable);
				}
			}
		}
	}
	return pAddress;
}

LPVOID CreateMemoryShare(int size, const char* name)
{
	//打开一个命名的内存映射文件对象  
	HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, 0, name);
	if (hMapFile == NULL)
	{
		//创建共享文件句柄 
		hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,   // 物理文件句柄
			NULL,   // 默认安全级别
			PAGE_READWRITE,   // 可读可写
			0,   // 高位文件大小
			size,   // 低位文件大小
			name   // 共享内存名称
		);
	}
	// 映射缓存区视图 , 得到指向共享内存的指针
	LPVOID lpBase = MapViewOfFile(
		hMapFile,            // 共享内存的句柄
		FILE_MAP_ALL_ACCESS, // 可读写许可
		0,
		0,
		size
	);
	return lpBase;

}


PVOID GetHwndDllAddressEx(HWND hwnd, char* dllname, LPCSTR lpProcName)
{


	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	HANDLE hProcee = ::OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD, 0, pid);

	MODULEENTRY32 me32;
	bool ret = GetModule(pid, dllname, me32);
	PVOID addr = 0;
	if (ret)
	{
		addr = GetProcAddressEx(hProcee, me32.hModule, lpProcName);
		//关闭进程
		CloseHandle(hProcee);
	}

	return addr;
}
///< 枚举窗口回调函数
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	EnumWindowsArg* pArg = (EnumWindowsArg*)lParam;
	DWORD dwProcessID = 0;
	// 通过窗口句柄取得进程ID
	::GetWindowThreadProcessId(hwnd, &dwProcessID);
	if (dwProcessID == pArg->dwProcessID)
	{
		pArg->hwndWindow = hwnd;
		// 找到了返回FALSE
		return FALSE;
	}
	// 没找到，继续找，返回TRUE
	return TRUE;
}
///< 通过进程ID获取窗口句柄
HWND GetWindowHwndByPID(DWORD dwProcessID)
{
	HWND hwndRet = NULL;
	EnumWindowsArg ewa;
	ewa.dwProcessID = dwProcessID;
	ewa.hwndWindow = NULL;
	EnumWindows(EnumWindowsProc, (LPARAM)&ewa);
	if (ewa.hwndWindow)
	{
		hwndRet = ewa.hwndWindow;
	}
	return hwndRet;
}



void  HexReversal(int hex, unsigned char* ret)
{

	DWORD H = hex;
	H = (H & 255) << 24 | ((H >> 8) & 255) << 16 | ((H >> 16) & 255) << 8 | (H >> 24) & 255;
	ret[3] = (byte)(0xff & H);
	ret[2] = (byte)((0xff00 & H) >> 8);
	ret[1] = (byte)((0xff0000 & H) >> 16);
	ret[0] = (byte)((0xff000000 & H) >> 24);
}

int GetProModuleHandleA(char* dllName, char* funName)
{
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA(dllName), funName);
	return (int)pfnStartAddr;
}



int DoInjection(LPCSTR DllPath, HWND  hwnd, HANDLE hProcess)
{
	if (hProcess == 0 || hwnd != 0)
	{
		hProcess = GetThePidOfTargetProcess(hwnd);
	}

	DWORD BufSize = strlen(DllPath) + 1;
	LPVOID AllocAddr = VirtualAllocEx(hProcess, NULL, BufSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, AllocAddr, DllPath, BufSize, NULL);
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	//句柄获取失败  释放
	if (NULL == pfnStartAddr)
	{
		Free(hProcess, 0, AllocAddr);
		return false;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pfnStartAddr, AllocAddr, 0, NULL);

	if (!hRemoteThread)
	{
		Free(hProcess, 0, AllocAddr);
		return false;
	}
	// 等待远线程结束
	WaitForSingleObject(hRemoteThread, INFINITE);
	// 取DLL在目标进程的句柄
	DWORD remoteModule;
	GetExitCodeThread(hRemoteThread, &remoteModule);
	Free(hProcess, hRemoteThread, AllocAddr);
	return remoteModule;

}

HANDLE GetThePidOfTargetProcess(HWND hwnd)
{
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	HANDLE hProcee = ::OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD, 0, pid);
	return hProcee;
}

int BytesToHexStr(char* bytes, int len, char* ret, bool space)
{
	std::string str = bytestohexstring(bytes, len, space);
	const char* c = str.c_str();
	strcpy(ret, c);
	return strlen(c);
}


typedef struct
{
	int type;   //0收包，1发包，2替换包 消息类型
	int len;    // 消息长度
	int hwnd;	//游戏窗口句柄
	int addr;	//消息地址
} MhMsgNotice;
void NoticeCallBack(MhMsg* msg)
{
	
	static std::mutex mx;
	if (MsgCallBack == 0 || MsgCallBack == nullptr)
	{
		return;
	}


	//打开订阅回调函数
	//获取进程
	HANDLE pro = GetThePidOfTargetProcess(MsgCallBack->hwnd);
	if (!pro)
	{
		return;
	}
	mx.lock();
	MhMsgNotice mn;
	mn.len = msg->len;//长度
	mn.type = msg->type;//消息类型

	static int init = 0;
	//数据存放地址
	static LPVOID dataAddr = nullptr;
	//参数传入地址
	static LPVOID prmAddr = nullptr;
	 
	if (msgRecvAddr == 0)
	{
		std::cout<< "释放重新装载"<<std::endl;
		//判断是否有内存残留 释放
		if (dataAddr != nullptr) { VirtualFreeEx(pro, dataAddr, 0, MEM_RELEASE); }
		if (prmAddr != nullptr) { VirtualFreeEx(pro, prmAddr, 0, MEM_RELEASE); }
		dataAddr = VirtualAllocEx(pro, NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
		prmAddr = VirtualAllocEx(pro, NULL, sizeof(mn), MEM_COMMIT, PAGE_READWRITE);
		msgRecvAddr = 1;
	}
	mn.hwnd = (int)MsgCallBack->mh_hwnd;
	mn.addr = (int)dataAddr;
	//写入数据
	WriteProcessMemory(pro, dataAddr, msg->body, msg->len, NULL);
	//写入参数
	WriteProcessMemory(pro, prmAddr, &mn, sizeof(mn), NULL);
	HANDLE   hRemoteThread = CreateRemoteThread(pro, NULL, 0, (PTHREAD_START_ROUTINE)MsgCallBack->callBack, prmAddr, 0, NULL);

	if (hRemoteThread == false)
	{
		MsgCallBack = 0;
	}
	WaitForSingleObject(hRemoteThread, INFINITE); //等待线程结束											  
	//释放申请的空间
	Free(pro, hRemoteThread, 0);

	mx.unlock();

}

void Free(HANDLE pro, HANDLE remoteThread, LPVOID allocAddr)
{

	if (allocAddr != 0)
	{
		VirtualFreeEx(pro, allocAddr, 0, MEM_RELEASE);
	}

	if (remoteThread != 0)
	{
		CloseHandle(remoteThread);
	}
	if (pro != 0)
	{

		CloseHandle(pro);
	}

}

void SetMHMsgAddr(MhSendMsg m)
{
	for (size_t i = 0; i < 32; i++)
	{
		if (sendMsgAddr[i].hwnd == 0)
		{
			sendMsgAddr[i] = m;
		}
	}
}

BOOL SendMsg(HWND hwnd, char* body, int len)
{
	int addr = 0;
	for (size_t i = 0; i < 32; i++)
	{
		if (sendMsgAddr[i].hwnd == hwnd)
		{
			addr = (int)sendMsgAddr[i].msgAddr;
		}

	}
	if (addr == 0)
	{
		return false;
	}

	//获取进程
	HANDLE pro = GetThePidOfTargetProcess(hwnd);
	BOOL ret = WriteProcessMemory(pro, (LPVOID)(addr + 1), &len, 4, NULL);
	ret = WriteProcessMemory(pro, (LPVOID)(addr + 5), body, len, NULL);
	//发送窗体消息
	SendMessage(hwnd, 28, 1, 0);
	SendMessage(hwnd, 262, 76, 0);
	return ret;
}

int ReplaceSendPkgByte(int v, int pkglen, int idx)
{
	static int inc = 0;
	if (inc == 0)
	{
		memset(rules, 0, sizeof(MapRule) * 4);

		unsigned char rep[] = { 0x27 ,0x02, 0x00 ,0x00 };
		RegisterSendPkgRule(0xF3, rep, 4);
		inc = 1;
	}

	static int head = 0;//头标记
	static int flag = 0;//替换标记位置
	static char bytes[4096];
	//获取头标记
	if (idx == 0) {
		head = v;
	}
	bytes[idx] = v;
	//返回结果
	int len = 0;
	int ret = 0;
	//判断是否是过滤的封包
	if (rules[head].head)
	{

		//如果是过滤包 返回
		len = rules[head].len;
		unsigned char  rep = rules[head].body[flag];
		if (idx > rules[head].len - 1)
		{
			return 0;
		}
		bytes[flag] = rep;
		ret = (len << 16) | rep;
		flag++;

	}


	if (pkglen - 1 == idx)
	{


		//收包完成，发送通知
		static MhMsg msg;
		memcpy(msg.body, bytes, pkglen);
		msg.len = pkglen;
		msg.type = 1;
		if (rules[head].head) {
			msg.type = 2;
		}
		NoticeCallBack(&msg);
		//归位操作
		head = 0;
		flag = 0;
	}

	return ret;
}
//注册替换封包的内容
//入参1：包头
//入参2：字节内容
//入参3：替换包的长度
void RegisterSendPkgRule(int head, unsigned char* body, int len) {

	MapRule rule;
	rule.head = head;
	rule.body = new unsigned char(len);
	memcpy(rule.body, body, 4);
	rule.len = len;
	rules[head] = rule;


}
