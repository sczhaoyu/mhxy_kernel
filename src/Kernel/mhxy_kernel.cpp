#include "mhxy_kernel.hpp"
MapRule   rules[255];
ProCallback* MsgCallBack = 0;//��Ϣ�ص�����
int msgRecvAddr = 0;//��Ϣ�ظ���ַ
MhSendMsg sendMsgAddr[32];//�λ���Ϣ���͵�ַ
void console(char* title) {
	//�򿪿���̨��������ʾ������Ϣ
	AllocConsole();
	//���ñ���
	SetConsoleTitleA(title);
	//�ض������
	freopen("CONOUT$", "w+t", stdout);
}
void  OpenConsole(char* title) {
	if (title == 0 || title == nullptr)
	{
		title = "������Ϣ";
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
	//��ȡǰ�������
	char* prev = new    char[start];
	memcpy(prev, bytes, start);
	//��ȡ��������
	int lastLen = bytesLen - (start + newBytesLen);
	char* last = new   char[lastLen];
	memcpy(last, bytes + start + newBytesLen, lastLen);

	//��������
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
	OpenConsole("��־��Ϣ");
	if (MsgCallBack!=nullptr)
	{
		delete MsgCallBack;
	}
	MsgCallBack = new ProCallback;
	MsgCallBack->callBack = pc->callBack;
	MsgCallBack->hwnd = pc->hwnd;
	MsgCallBack->mh_hwnd = pc->mh_hwnd;
	//��ʼ��ϵͳ
	msgRecvAddr = 0;

}
int InitSystem(char* dllPath, int SetMhMsgCallBack, int RecvMhxyPkgAddr, int ReplaceSendPkgByteAddr, HWND myHwnd, void* funcCallBack, HWND mhHwnd)
{


	//��ȡ����
	HANDLE pro = GetThePidOfTargetProcess(mhHwnd);
	//�����ڴ�
	LPVOID addr = VirtualAllocEx(pro, 0, 4096, MEM_COMMIT, 64);

	ProCallback prc;
	prc.callBack = funcCallBack;
	prc.hwnd = myHwnd;
	prc.mh_hwnd = mhHwnd;
	//���ûص�����
	LPVOID AllocAddr = VirtualAllocEx(pro, NULL, sizeof(ProCallback), MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(pro, AllocAddr, &prc, sizeof(ProCallback), NULL);


	HANDLE   hRemoteThread = CreateRemoteThread(pro, NULL, 0, (PTHREAD_START_ROUTINE)SetMhMsgCallBack, AllocAddr, 0, NULL);
	// �ȴ�Զ�߳̽���
	WaitForSingleObject(hRemoteThread, INFINITE);
	Free(0, hRemoteThread, AllocAddr);



	unsigned char code[] = { 136,12,16,93,131,248,2,115,3,194,12,0,96,82,102,139,90,1,15,183,219,131,195,2,83,80,187,144,34,6,99,255,211,131,196,12,97,194,12,0 };
	//�ɵ�ַ
	unsigned char dllModule[] = { 144,34,6,99 };
	int idx = FindBytes(code, sizeof(code), dllModule, 4, 0);



	//ģ���ַת16����
	unsigned char   newDllModule[4];
	HexReversal(RecvMhxyPkgAddr, newDllModule);

	unsigned char* newCode = new unsigned char[2048];
	memset(newCode, 0, 2048);
	//�滻ģ��ľɵ�ַ
	int len = ReplaceBytes(code, sizeof(code), idx, newDllModule, sizeof(newDllModule), newCode);

	LPVOID codeAddr = (LPVOID)((int)addr + 1024);
	//д���հ�����
	WriteProcessMemory(pro, codeAddr, newCode, 2048, NULL);
	//������ַ
	int mhCodeLen = 7245824;//��С
	int moudleStart = 286000000;//ģ����ʼ��ַ
	unsigned char* mhCodes = new  unsigned char[mhCodeLen];
	memset(mhCodes, 0, mhCodeLen);
	ReadProcessMemory(pro, (LPCVOID)moudleStart, mhCodes, mhCodeLen, 0);
	unsigned char recvPkg[] = { 139,18,139,69,8,138,77,16 };// { 139, 68, 36, 4, 138, 76, 36, 12 };
	//�����հ�������
	idx = FindBytes(mhCodes, mhCodeLen, recvPkg, sizeof(recvPkg), 0);
	//������ת�Ĵ����ַ
	int jmp = moudleStart + idx+8;
	newDllModule[4];
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned char jmpBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//д���հ���ת
	WriteProcessMemory(pro, (LPVOID)jmp, jmpBytes, sizeof(jmpBytes), NULL);
	//�޸�д���ַ
	codeAddr = (LPVOID)((int)codeAddr + len);

	//��������
	memset(newCode, 0, 2048);
	unsigned char sendCode[] = { 141,95,16,131,127,20,16,15,130,4,0,0,0,139,63,117,0,15,190,4,58,15,182,201,95,49,200,60,241,15,132,18,0,0,0,128,61,0,0,183,7,0,15,133,29,0,0,0,233,69,0,0,0,185,1,0,0,0,136,13,0,0,183,7,139,13,1,0,183,7,137,11,233,0,0,0,0,15,182,130,5,0,183,7,53,0,255,255,255,96,139,3,131,232,1,187,0,0,0,0,185,1,0,0,0,57,194,15,68,203,136,13,0,0,183,7,97,233,0,0,0,0,96,37,255,0,0,0,82,255,51,80,187,96,36,4,99,255,211,137,68,36,36,131,196,12,97,233,0,0,0,0,131,124,36,248,0,117,5,233,30,0,0,0,139,68,36,248,37,0,0,255,255,193,232,16,137,3,139,68,36,248,37,255,255,0,0,53,0,255,255,255,117,0,91,89,194,8,0 };
	//�µķ�����ַ
	unsigned char   sendAddr[4];
	HexReversal((int)addr, sendAddr);
	//�ɵķ�����ַ
	unsigned char oldSendAddr[4] = { 0x00,0x00,0xB7,0x07 };
	//��һ��
	idx = FindBytes(sendCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(sendCode, sizeof(sendCode), idx, sendAddr, sizeof(sendAddr), newCode);

	//�ڶ���
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);

	//������
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);


	//���λ��
	unsigned char oldSendAddrFlag[4] = { 0x01,0x00,0xB7,0x07 };
	unsigned char   sendAddrFlag[4];
	HexReversal((int)addr + 1, sendAddrFlag);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrFlag, sizeof(oldSendAddrFlag), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrFlag, sizeof(sendAddrFlag), newCode);

	//����λ��
	unsigned char oldSendAddrLen[4] = { 0x05,0x00,0xB7,0x07 };
	unsigned char   sendAddrLen[4];
	HexReversal((int)addr + 5, sendAddrLen);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrLen, sizeof(oldSendAddrLen), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrLen, sizeof(sendAddrLen), newCode);




	//�滻������ַ
	unsigned char oldSendCall[4] = { 0x60, 0x24, 0x04 ,0x63 };
	unsigned char   sendCall[4];
	HexReversal(ReplaceSendPkgByteAddr, sendCall);
	idx = FindBytes(newCode, mhCodeLen, oldSendCall, sizeof(oldSendCall), 0);
	len = ReplaceBytes(newCode, len, idx, sendCall, sizeof(sendCall), newCode);
	//д�뷢������
	WriteProcessMemory(pro, codeAddr, newCode, len, NULL);

	//��������ת
	unsigned char sendPkg[] = { 126, 8, 138, 194, 179, 53, 246, 235 };
	//���ҷ���������
	idx = FindBytes(mhCodes, mhCodeLen, sendPkg, sizeof(sendPkg), 0);

	//������ת�Ĵ����ַ
	jmp = moudleStart + idx + 13;
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned	char jmpSendBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//д���հ���ת
	WriteProcessMemory(pro, (LPVOID)jmp, jmpSendBytes, sizeof(jmpSendBytes), NULL);



	CloseHandle(pro);
	delete mhCodes;
	msgRecvAddr = 0;//����ϵͳ��־

	MhSendMsg mm;
	mm.hwnd = mhHwnd;
	mm.msgAddr = addr;

	SetMHMsgAddr(mm);//������Ϣ���͵�ַ
	return (int)addr;
}

int InitSystemRemoteThread(ProCallback* prc)
{
	//��ȡ����
	HANDLE pro = GetCurrentProcess();
	//�����ڴ�
	LPVOID addr = VirtualAllocEx(pro, 0, 4096, MEM_COMMIT, 64);
	//���ûص�����
	SetMhMsgCallBack(prc);
	unsigned char code[] = { 136,12,16,131,248,2,15,131,3,0,0,0,194,12,0,96,82,102,139,90,1,15,183,219,131,195,2,83,80,187,144,34,6,99,255,211,131,196,12,97,194,12,0 };
	//�ɵ�ַ
	unsigned char dllModule[] = { 144,34,6,99 };
	int idx = FindBytes(code, sizeof(code), dllModule, 4, 0);

	//ģ���ַת16����
	unsigned char   newDllModule[4];
	HexReversal((int)RecvMhxyPkg, newDllModule);

	unsigned char* newCode = new unsigned char[2048];
	memset(newCode, 0, 2048);
	//�滻ģ��ľɵ�ַ
	int len = ReplaceBytes(code, sizeof(code), idx, newDllModule, sizeof(newDllModule), newCode);

	LPVOID codeAddr = (LPVOID)((int)addr + 1024);
	//д���հ�����
	WriteProcessMemory(pro, codeAddr, newCode, 2048, NULL);
	//������ַ
	int mhCodeLen = 7245824;//��С
	int moudleStart = 286261248;//ģ����ʼ��ַ
	unsigned char* mhCodes = new  unsigned char[mhCodeLen];
	memset(mhCodes, 0, mhCodeLen);
	ReadProcessMemory(pro, (LPCVOID)moudleStart, mhCodes, mhCodeLen, 0);
	unsigned char recvPkg[] = { 139, 68, 36, 4, 138, 76, 36, 12 };
	//�����հ�������
	idx = FindBytes(mhCodes, mhCodeLen, recvPkg, sizeof(recvPkg), 0);
	//������ת�Ĵ����ַ
	int jmp = moudleStart + idx + 8;
	newDllModule[4];
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned char jmpBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//д���հ���ת
	WriteProcessMemory(pro, (LPVOID)jmp, jmpBytes, sizeof(jmpBytes), NULL);
	//�޸�д���ַ
	codeAddr = (LPVOID)((int)codeAddr + len);

	//��������
	memset(newCode, 0, 2048);
	unsigned char sendCode[] = { 141,95,16,131,127,20,16,15,130,4,0,0,0,139,63,117,0,15,190,4,58,15,182,201,95,49,200,60,241,15,132,18,0,0,0,128,61,0,0,183,7,0,15,133,29,0,0,0,233,69,0,0,0,185,1,0,0,0,136,13,0,0,183,7,139,13,1,0,183,7,137,11,233,0,0,0,0,15,182,130,5,0,183,7,53,0,255,255,255,96,139,3,131,232,1,187,0,0,0,0,185,1,0,0,0,57,194,15,68,203,136,13,0,0,183,7,97,233,0,0,0,0,96,37,255,0,0,0,82,255,51,80,187,96,36,4,99,255,211,137,68,36,36,131,196,12,97,233,0,0,0,0,131,124,36,248,0,117,5,233,30,0,0,0,139,68,36,248,37,0,0,255,255,193,232,16,137,3,139,68,36,248,37,255,255,0,0,53,0,255,255,255,117,0,91,89,194,8,0 };
	//�µķ�����ַ
	unsigned char   sendAddr[4];
	HexReversal((int)addr, sendAddr);
	//�ɵķ�����ַ
	unsigned char oldSendAddr[4] = { 0x00,0x00,0xB7,0x07 };
	//��һ��
	idx = FindBytes(sendCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(sendCode, sizeof(sendCode), idx, sendAddr, sizeof(sendAddr), newCode);

	//�ڶ���
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);

	//������
	idx = FindBytes(newCode, mhCodeLen, oldSendAddr, sizeof(oldSendAddr), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddr, sizeof(sendAddr), newCode);


	//���λ��
	unsigned char oldSendAddrFlag[4] = { 0x01,0x00,0xB7,0x07 };
	unsigned char   sendAddrFlag[4];
	HexReversal((int)addr + 1, sendAddrFlag);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrFlag, sizeof(oldSendAddrFlag), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrFlag, sizeof(sendAddrFlag), newCode);

	//����λ��
	unsigned char oldSendAddrLen[4] = { 0x05,0x00,0xB7,0x07 };
	unsigned char   sendAddrLen[4];
	HexReversal((int)addr + 5, sendAddrLen);
	idx = FindBytes(newCode, mhCodeLen, oldSendAddrLen, sizeof(oldSendAddrLen), 0);
	len = ReplaceBytes(newCode, len, idx, sendAddrLen, sizeof(sendAddrLen), newCode);




	//�滻������ַ
	unsigned char oldSendCall[4] = { 0x60, 0x24, 0x04 ,0x63 };
	unsigned char   sendCall[4];
	HexReversal((int)ReplaceSendPkgByte, sendCall);
	idx = FindBytes(newCode, mhCodeLen, oldSendCall, sizeof(oldSendCall), 0);
	len = ReplaceBytes(newCode, len, idx, sendCall, sizeof(sendCall), newCode);
	//д�뷢������
	WriteProcessMemory(pro, codeAddr, newCode, len, NULL);

	//��������ת
	unsigned char sendPkg[] = { 126, 8, 138, 194, 179, 53, 246, 235 };
	//���ҷ���������
	idx = FindBytes(mhCodes, mhCodeLen, sendPkg, sizeof(sendPkg), 0);

	//������ת�Ĵ����ַ
	jmp = moudleStart + idx + 13;
	HexReversal((int)codeAddr - jmp - 0x05, newDllModule);
	unsigned	char jmpSendBytes[5] = { 233, newDllModule[0], newDllModule[1], newDllModule[2], newDllModule[3] };
	//д���հ���ת
	WriteProcessMemory(pro, (LPVOID)jmp, jmpSendBytes, sizeof(jmpSendBytes), NULL);

	delete mhCodes;
	msgRecvAddr = 0;//����ϵͳ��־
	return (int)addr;
}

//�ͷſ���̨
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
	//��ȡԶ�̽��̵�ģ�����
	HANDLE module_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process);
	if (INVALID_HANDLE_VALUE == module_handle)
	{

		return false;
	}
	//����ģ�飬�ҵ�ָ��ģ��
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
	//���ز��ҽ��
	return is_found;
}
//�����ȡ������ַ
PVOID GetProcAddressEx(HANDLE hProc, HMODULE hModule, LPCSTR lpProcName)
{
	PVOID pAddress = NULL;
	SIZE_T OptSize;
	IMAGE_DOS_HEADER DosHeader;
	SIZE_T ProcNameLength = lstrlenA(lpProcName) + sizeof(CHAR);//'\0'

																//��DOSͷ
	if (ReadProcessMemory(hProc, hModule, &DosHeader, sizeof(DosHeader), &OptSize))
	{
		IMAGE_NT_HEADERS NtHeader;

		//��NTͷ
		if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + DosHeader.e_lfanew), &NtHeader, sizeof(NtHeader), &OptSize))
		{
			IMAGE_EXPORT_DIRECTORY ExpDir;
			SIZE_T ExportVirtualAddress = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

			//�������
			if (ExportVirtualAddress && ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExportVirtualAddress), &ExpDir, sizeof(ExpDir), &OptSize))
			{
				if (ExpDir.NumberOfFunctions)
				{
					//x64����:��ַ������RVA������������4�ֽڻ���8�ֽ�???
					SIZE_T* pProcAddressTable = (SIZE_T*)GlobalAlloc(GPTR, ExpDir.NumberOfFunctions * sizeof(SIZE_T));

					//��������ַ��
					if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfFunctions), pProcAddressTable, ExpDir.NumberOfFunctions * sizeof(PVOID), &OptSize))
					{
						//x64����:����������RVA������������4�ֽڻ���8�ֽ�???
						SIZE_T* pProcNamesTable = (SIZE_T*)GlobalAlloc(GPTR, ExpDir.NumberOfNames * sizeof(SIZE_T));

						//���������Ʊ�
						if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfNames), pProcNamesTable, ExpDir.NumberOfNames * sizeof(PVOID), &OptSize))
						{
							CHAR* pProcName = (CHAR*)GlobalAlloc(GPTR, ProcNameLength);

							//������������
							for (DWORD i = 0; i < ExpDir.NumberOfNames; i++)
							{
								if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + pProcNamesTable[i]), pProcName, ProcNameLength, &OptSize))
								{
									if (RtlEqualMemory(lpProcName, pProcName, ProcNameLength))
									{
										//x64����:�����ڵ�ַ��������������������2�ֽڻ���???
										WORD NameOrdinal;

										//��ȡ�����ڵ�ַ�������
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
	//��һ���������ڴ�ӳ���ļ�����  
	HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, 0, name);
	if (hMapFile == NULL)
	{
		//���������ļ���� 
		hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,   // �����ļ����
			NULL,   // Ĭ�ϰ�ȫ����
			PAGE_READWRITE,   // �ɶ���д
			0,   // ��λ�ļ���С
			size,   // ��λ�ļ���С
			name   // �����ڴ�����
		);
	}
	// ӳ�仺������ͼ , �õ�ָ�����ڴ��ָ��
	LPVOID lpBase = MapViewOfFile(
		hMapFile,            // �����ڴ�ľ��
		FILE_MAP_ALL_ACCESS, // �ɶ�д���
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
		//�رս���
		CloseHandle(hProcee);
	}

	return addr;
}
///< ö�ٴ��ڻص�����
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	EnumWindowsArg* pArg = (EnumWindowsArg*)lParam;
	DWORD dwProcessID = 0;
	// ͨ�����ھ��ȡ�ý���ID
	::GetWindowThreadProcessId(hwnd, &dwProcessID);
	if (dwProcessID == pArg->dwProcessID)
	{
		pArg->hwndWindow = hwnd;
		// �ҵ��˷���FALSE
		return FALSE;
	}
	// û�ҵ��������ң�����TRUE
	return TRUE;
}
///< ͨ������ID��ȡ���ھ��
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

	//�����ȡʧ��  �ͷ�
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
	// �ȴ�Զ�߳̽���
	WaitForSingleObject(hRemoteThread, INFINITE);
	// ȡDLL��Ŀ����̵ľ��
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
	int type;   //0�հ���1������2�滻�� ��Ϣ����
	int len;    // ��Ϣ����
	int hwnd;	//��Ϸ���ھ��
	int addr;	//��Ϣ��ַ
} MhMsgNotice;
void NoticeCallBack(MhMsg* msg)
{
	
	static std::mutex mx;
	if (MsgCallBack == 0 || MsgCallBack == nullptr)
	{
		return;
	}


	//�򿪶��Ļص�����
	//��ȡ����
	HANDLE pro = GetThePidOfTargetProcess(MsgCallBack->hwnd);
	if (!pro)
	{
		return;
	}
	mx.lock();
	MhMsgNotice mn;
	mn.len = msg->len;//����
	mn.type = msg->type;//��Ϣ����

	static int init = 0;
	//���ݴ�ŵ�ַ
	static LPVOID dataAddr = nullptr;
	//���������ַ
	static LPVOID prmAddr = nullptr;
	 
	if (msgRecvAddr == 0)
	{
		std::cout<< "�ͷ�����װ��"<<std::endl;
		//�ж��Ƿ����ڴ���� �ͷ�
		if (dataAddr != nullptr) { VirtualFreeEx(pro, dataAddr, 0, MEM_RELEASE); }
		if (prmAddr != nullptr) { VirtualFreeEx(pro, prmAddr, 0, MEM_RELEASE); }
		dataAddr = VirtualAllocEx(pro, NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
		prmAddr = VirtualAllocEx(pro, NULL, sizeof(mn), MEM_COMMIT, PAGE_READWRITE);
		msgRecvAddr = 1;
	}
	mn.hwnd = (int)MsgCallBack->mh_hwnd;
	mn.addr = (int)dataAddr;
	//д������
	WriteProcessMemory(pro, dataAddr, msg->body, msg->len, NULL);
	//д�����
	WriteProcessMemory(pro, prmAddr, &mn, sizeof(mn), NULL);
	HANDLE   hRemoteThread = CreateRemoteThread(pro, NULL, 0, (PTHREAD_START_ROUTINE)MsgCallBack->callBack, prmAddr, 0, NULL);

	if (hRemoteThread == false)
	{
		MsgCallBack = 0;
	}
	WaitForSingleObject(hRemoteThread, INFINITE); //�ȴ��߳̽���											  
	//�ͷ�����Ŀռ�
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

	//��ȡ����
	HANDLE pro = GetThePidOfTargetProcess(hwnd);
	BOOL ret = WriteProcessMemory(pro, (LPVOID)(addr + 1), &len, 4, NULL);
	ret = WriteProcessMemory(pro, (LPVOID)(addr + 5), body, len, NULL);
	//���ʹ�����Ϣ
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

	static int head = 0;//ͷ���
	static int flag = 0;//�滻���λ��
	static char bytes[4096];
	//��ȡͷ���
	if (idx == 0) {
		head = v;
	}
	bytes[idx] = v;
	//���ؽ��
	int len = 0;
	int ret = 0;
	//�ж��Ƿ��ǹ��˵ķ��
	if (rules[head].head)
	{

		//����ǹ��˰� ����
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


		//�հ���ɣ�����֪ͨ
		static MhMsg msg;
		memcpy(msg.body, bytes, pkglen);
		msg.len = pkglen;
		msg.type = 1;
		if (rules[head].head) {
			msg.type = 2;
		}
		NoticeCallBack(&msg);
		//��λ����
		head = 0;
		flag = 0;
	}

	return ret;
}
//ע���滻���������
//���1����ͷ
//���2���ֽ�����
//���3���滻���ĳ���
void RegisterSendPkgRule(int head, unsigned char* body, int len) {

	MapRule rule;
	rule.head = head;
	rule.body = new unsigned char(len);
	memcpy(rule.body, body, 4);
	rule.len = len;
	rules[head] = rule;


}
