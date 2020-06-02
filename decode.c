#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>
#include <time.h>

void UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr);
LPVOID GetLastSecData(LPSTR lpszFile, DWORD& fileSize);
LPVOID AllocShellSize(LPSTR shellDirectory, HANDLE shellProcess, LPVOID encryptFileBuffer);
VOID GetNtHeaderInfo(LPVOID pFileBuffer, DWORD& ImageBase, DWORD& ImageSize);
VOID GetEncryptFileContext(LPVOID pFileBuffer, DWORD& OEP, DWORD& ImageBase);
LPVOID FileBufferToImageBuffer(BYTE * decodebuffer, DWORD& size);
void DoRelocation(LPVOID pFileBuffer, void* OldBase, void* NewBase);
BOOL HasRelocationTable(LPVOID pFileBuffer);
int main()
{
    WCHAR shellDirectory[100] = L"C:\\Users\\pisanbao\\Desktop\\shell.exe"; //这是加壳后的程序
    DWORD encryptSize = 0;

    LPVOID encryptFileBuffer = NULL;
    encryptFileBuffer = GetLastSecData("C:\\Users\\pisanbao\\Desktop\\shell.exe", encryptSize);
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    si.cb = sizeof(si);
	::CreateProcess(shellDirectory, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	//int x = GetLastError();
	//printf("%d\n", x);
	char szTempStr[256] = { 0 };
	sprintf(szTempStr, "process_information %x , %x \n", pi.hProcess, pi.hThread);
	CONTEXT contx;
    contx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &contx);
    DWORD dwEntryPoint = contx.Eax;
    char* baseAddress = (CHAR*)contx.Ebx + 8;
    TCHAR szBuffer[4] = { 0 };
    ReadProcessMemory(pi.hProcess, baseAddress, szBuffer, 4, NULL);
    int* fileImageBase;
    fileImageBase = (int*)szBuffer;
    DWORD shellImageBase = *fileImageBase;
    UnloadShell(pi.hProcess, shellImageBase);
	LPVOID p = AllocShellSize("C:\\Users\\pisanbao\\Desktop\\shell.exe", pi.hProcess, encryptFileBuffer);
	DWORD pEncryptImageSize = 0;
	LPVOID pEncryptImageBuffer = FileBufferToImageBuffer((BYTE *)encryptFileBuffer, pEncryptImageSize);//将加密的源程序数据拷贝到新分配的内存空间
	unsigned long old;
	WriteProcessMemory(pi.hProcess, (void*)(contx.Ebx + 8), &p, sizeof(DWORD), &old);

	if (WriteProcessMemory(pi.hProcess, p, pEncryptImageBuffer, pEncryptImageSize, &old))
	{// 复制PE数据到shell的进程空间中  

		DWORD encryptFileOEP = 0;
		DWORD encryptFileImageBase = 0;

		GetEncryptFileContext(encryptFileBuffer, encryptFileOEP, encryptFileImageBase);

		contx.ContextFlags = CONTEXT_FULL;

		//修复入口地址为源程序的入口
		contx.Eax = encryptFileOEP + (DWORD)p;
		SetThreadContext(pi.hThread, &contx);// 更新主进程的运行环境为源程序的运行环境

		LPVOID szBufferTemp = malloc(pEncryptImageSize);
		memset(szBufferTemp, 0, pEncryptImageSize);
		ReadProcessMemory(pi.hProcess, p, szBufferTemp, pEncryptImageSize, NULL);
		/*
		//////这个是测试用的 实际壳程序将加密文件解密后直接跳转到源程序的入口执行：脱壳后程序保存到文件////////
		MemeryTOFile(szBufferTemp, "111111.exe");
		///////////////////////////////////////////////////////////////////////////////////////////////////////
		*/
		ResumeThread(pi.hThread);// 恢复执行主线程  
		CloseHandle(pi.hThread);
	}
	return 0;
}
void UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr)
{
    typedef unsigned long(__stdcall* pfZwUnmapViewOfSection)(unsigned long, unsigned long);
    pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;
    BOOL res = FALSE;
    HMODULE m = LoadLibrary((LPWSTR)"ntdll.dll");
    if (m) {
        ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");

        if (ZwUnmapViewOfSection)
            res = (ZwUnmapViewOfSection((unsigned long)ProcHnd, BaseAddr) == 0);  //取消映射目标进程的内存
        FreeLibrary(m);
    }
    return;
}
LPVOID FileBufferToImageBuffer(BYTE * decodebuffer, DWORD& size)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader_LAST = NULL;

	//Header信息
	pDosHeader = (PIMAGE_DOS_HEADER)decodebuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)decodebuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pSectionHeader_LAST = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + (pPEHeader->NumberOfSections-1) * 40);

	unsigned int fileLength = pSectionHeader_LAST->PointerToRawData + pSectionHeader_LAST->SizeOfRawData;
	size = pNTHeader->OptionalHeader.SizeOfImage;
	BYTE * pEncryptBuffer = (BYTE *)malloc(size);
	memset(pEncryptBuffer, 0, size);
	memcpy(pEncryptBuffer, decodebuffer, pNTHeader->OptionalHeader.SizeOfHeaders);
	int i;
	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		memcpy(pEncryptBuffer + pSectionHeader->VirtualAddress, decodebuffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	BYTE * pNew = pEncryptBuffer;

	BYTE * pOld = (BYTE*)((DWORD)decodebuffer + pSectionHeader_LAST->PointerToRawData);

	pEncryptBuffer = pOld;

	return pEncryptBuffer;
}
LPVOID GetLastSecData(LPSTR lpszFile, DWORD& fileSize)
{
	FILE* a = fopen(lpszFile, "rb");
	fseek(a, 0, SEEK_END);
	fileSize = ftell(a);
	fseek(a, 0, SEEK_SET);
	LPVOID pFileBuffer = calloc(1, fileSize);
	fread(pFileBuffer, fileSize, 1, a);
	fclose(a);
	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return NULL;
	}


	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader_LAST = NULL;

	//Header信息
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pSectionHeader_LAST = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + (pPEHeader->NumberOfSections-1) * 40);

	unsigned int fileLength = pSectionHeader_LAST->PointerToRawData + pSectionHeader_LAST->SizeOfRawData;
	fileSize = pSectionHeader_LAST->SizeOfRawData;
	LPVOID pEncryptBuffer = malloc(fileSize);
	memset(pEncryptBuffer, 0, fileSize);
	CHAR* pNew = (CHAR*)pEncryptBuffer;

	CHAR* pOld = (CHAR*)((DWORD)pFileBuffer + pSectionHeader_LAST->PointerToRawData);

	pEncryptBuffer = pOld;

	return pEncryptBuffer;
}
LPVOID AllocShellSize(LPSTR shellDirectory, HANDLE shellProcess, LPVOID encryptFileBuffer)
{
	typedef void* (__stdcall* pfVirtualAllocEx)(unsigned long, void*, unsigned long, unsigned long, unsigned long);
	pfVirtualAllocEx MyVirtualAllocEx = NULL;
	MyVirtualAllocEx = (pfVirtualAllocEx)GetProcAddress(GetModuleHandle((LPCWSTR)"Kernel32.dll"), "VirtualAllocEx"); //获取VirtualAllocEx 函数地址
	FILE* a = fopen(shellDirectory, "rb");
	fseek(a, 0, SEEK_END);
	unsigned long long fileSize = ftell(a);
	fseek(a, 0, SEEK_SET);
	LPVOID pShellBuffer = calloc(1, fileSize);
	fread(pShellBuffer, fileSize, 1, a);
	fclose(a);

	DWORD shellImageBase = 0;
	DWORD shellImageSize = 0;
	DWORD encryptImageBase = 0;
	DWORD encryptImageSize = 0;

	//获得ImageBase ImageSize， 进行信息比较
	GetNtHeaderInfo(pShellBuffer, shellImageBase, shellImageSize);
	GetNtHeaderInfo(encryptFileBuffer, encryptImageBase, encryptImageSize);

	if (shellImageBase == 0 || shellImageSize == 0 || encryptImageBase == 0 || encryptImageSize == 0)
	{
		MessageBoxA(0, "申请空间失败", "失败", 0);
		return NULL;
	}

	void* p = NULL;

	//在指定进程的指定位置分配内存
	/*
		VirtualAllocEx：在指定进程的虚拟空间保留或提交内存区域，除非指定MEM_RESET参数，否则将该内存区域置0。
		LPVOID VirtualAllocEx(
		HANDLE hProcess, // 申请内存所在的进程句柄
		LPVOID lpAddress, // 保留页面的内存地址；一般用NULL自动分配
		SIZE_T dwSize, // 欲分配的内存大小，字节单位；注意实际分 配的内存大小是页内存大小的整数倍
		DWORD flAllocationType,
		DWORD flProtect
	*/
	//如果指定位置内存没有被占用，则取 MAX(shellImageSize,encryptImageSize)
	if (shellImageBase == encryptImageBase)
	{
		shellImageSize = (shellImageSize >= encryptImageSize) ? shellImageSize : encryptImageSize;
		// 最小的分配方式，具体用法查MSDN，分配失败会返回NULL
		p = VirtualAllocEx(shellProcess, (void*)shellImageBase, shellImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//int x = GetLastError();
		//printf("%d\n", x);
	}

	// 指定位置被占用 & 进程中有重定位表
	if ((p == NULL) && HasRelocationTable(encryptFileBuffer)) {
		//任意位置分配空间
		p = VirtualAllocEx(shellProcess, NULL, encryptImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//重定位处理
		if (p) {
			DoRelocation(encryptFileBuffer, (void*)encryptImageBase, p);
		}
		else {

			MessageBoxA(0, "申请空间失败3", "失败3", 0);
			return NULL;
		}
	}


	return p;
}

VOID GetNtHeaderInfo(LPVOID pFileBuffer, DWORD& ImageBase, DWORD& ImageSize)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}

	//MZ标志
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}

	//DOS头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//判断是否是有效的PE 
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);

	//NT头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);

	//可选择PE头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);


	//获取信息
	ImageBase = pOptionHeader->ImageBase;
	ImageSize = pOptionHeader->SizeOfImage;

}

VOID GetEncryptFileContext(LPVOID pFileBuffer, DWORD& OEP, DWORD& ImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//pFileBuffer= ReadPEFile(lpszFile);

	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}

	//MZ标志
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}
	//DOS头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//判断是否是有效的PE 
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);

	//PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);

	//可选择PE头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	//获取信息
	OEP = pOptionHeader->AddressOfEntryPoint;
	ImageBase = pOptionHeader->ImageBase;

}
void DoRelocation(LPVOID pFileBuffer, void* OldBase, void* NewBase)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS peH = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);

	unsigned long Delta = (unsigned long)NewBase - peH->OptionalHeader.ImageBase;
	_IMAGE_BASE_RELOCATION *p = (_IMAGE_BASE_RELOCATION*)((unsigned long)OldBase
		+ peH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (p->VirtualAddress + p->SizeOfBlock)
	{
		unsigned short* pw = (unsigned short*)((int)p + sizeof(*p));
		for (unsigned int i = 1; i <= (p->SizeOfBlock - sizeof(*p)) / 2; ++i)
		{
			if ((*pw) & 0xF000 == 0x3000) {
				unsigned long* t = (unsigned long*)((unsigned long)(OldBase)+p->VirtualAddress + ((*pw) & 0x0FFF));
				*t += Delta;
			}
			++pw;
		}
		p = (_IMAGE_BASE_RELOCATION*)pw;
	}
}

BOOL HasRelocationTable(LPVOID pFileBuffer)
{

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY DataDirectory = NULL;

	//Header信息
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//定位Directory_Data;
	DataDirectory = pOptionHeader->DataDirectory;

	return (DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
		&& (DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
}
