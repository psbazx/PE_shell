#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>

LPVOID FileBufferToImageBuffer(BYTE* decodebuffer, DWORD& size);

int main()
{
    FILE* a;
    FILE* b;
    FILE* c;
    int i,j;
    const char shelladdr[] = "C:\\Users\\pisanbao\\Desktop\\decode_shell.exe";//shell路径
    const char srcaddr[] = "C:\\Users\\pisanbao\\Desktop\\thread_func.exe";//src路径
    a = fopen(srcaddr, "rb");
    fseek(a, 0, SEEK_END);
    unsigned long long filesize = ftell(a);
    fseek(a, 0, SEEK_SET);
    DWORD* filebuffer = (DWORD *)calloc(1, filesize);
    fread(filebuffer, filesize, 1, a);
    fclose(a);
    // file buffer get
    IMAGE_DOS_HEADER* filedosheader = (IMAGE_DOS_HEADER*)filebuffer;
    IMAGE_NT_HEADERS* filentheader = (IMAGE_NT_HEADERS*)((BYTE*)filebuffer + filedosheader->e_lfanew);
    IMAGE_SECTION_HEADER* filesection = (IMAGE_SECTION_HEADER*)((BYTE*)filebuffer + filedosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + filentheader->FileHeader.SizeOfOptionalHeader+40*(filentheader->FileHeader.NumberOfSections-1));
    filesize = filesection->PointerToRawData + filesection->SizeOfRawData;
    b = fopen(shelladdr, "rb");
    fseek(b, 0, SEEK_END);
    unsigned long long shellsize = ftell(b);
    fseek(b, 0, SEEK_SET);
    DWORD* shellbuffer = (DWORD*)calloc(1, shellsize);
    fread(shellbuffer, shellsize, 1, b);
    fclose(b);
    //shell buffer get
    c = fopen("C:\\Users\\pisanbao\\Desktop\\shell.exe", "ab+");
    IMAGE_DOS_HEADER * shelldosheader = (IMAGE_DOS_HEADER *)shellbuffer;
    IMAGE_NT_HEADERS* shellntheader = (IMAGE_NT_HEADERS*)((BYTE *)shellbuffer + shelldosheader->e_lfanew);
    IMAGE_SECTION_HEADER * shellsection = (IMAGE_SECTION_HEADER *)((BYTE*)shellbuffer + shelldosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + shellntheader->FileHeader.SizeOfOptionalHeader);
    for (i = 0; i < shellntheader->FileHeader.NumberOfSections; i++)
        shellsection++;
    WORD temp = shelldosheader->e_lfanew;
    DWORD tempsize = shellntheader->OptionalHeader.SizeOfHeaders;
    shelldosheader->e_lfanew = sizeof(IMAGE_DOS_HEADER);    
    unsigned long long realimage = filesize;

    if (filesize % 0x1000)
    {
        realimage = ((filesize / 0x1000) + 1) * 0x1000;
    }
    else
    {
        realimage = filesize;
    }
    //unsigned long long tempimage = shellntheader->OptionalHeader.SizeOfImage;
    strcpy((char *)shellsection->Name,".psb");//特征名
    unsigned long long count1;
    if (filesize % 0x200)
    {
        count1 = ((filesize / 0x200) + 1) * 0x200;
    }
    else
    {
        count1 = filesize;
    }
    //新增节主要注意的是要把新增的pe当作一段数据来看
    IMAGE_SECTION_HEADER* tempsection = shellsection;
    tempsection--;
    unsigned long long temptemp;
    DWORD imgsize = filentheader->OptionalHeader.SizeOfImage;
    if (tempsection->Misc.VirtualSize % 0x1000)
    {
        temptemp = ((tempsection->Misc.VirtualSize / 0x1000) + 1) * 0x1000;
    }
    else
    {
        temptemp = tempsection->Misc.VirtualSize;
    }
    unsigned long long realsize = tempsection->SizeOfRawData + tempsection->PointerToRawData;
    shellsection->Misc.VirtualSize = imgsize;
    shellsection->VirtualAddress = tempsection->VirtualAddress + temptemp;
    shellsection->SizeOfRawData = imgsize;
    shellsection->PointerToRawData = realsize;//这边踩坑了，有些编译器会在最后节后面加东西导致文件不对齐
    shellsection->Characteristics = 0xe0500060;
    shellntheader->FileHeader.NumberOfSections += 1;        //节数+1  
    shellntheader->OptionalHeader.SizeOfImage = shellsection->VirtualAddress + imgsize;
    for (i = temp,j=0; i < tempsize; i++,j++)
    {
        *((BYTE*)shellbuffer + sizeof(IMAGE_DOS_HEADER)+j) = *((BYTE*)shellbuffer + i);
        *((BYTE*)shellbuffer + i) = 0;
    }
    fwrite((BYTE*)shellbuffer, realsize, 1, c);
    //新增节完成
    //加密pe最后填充
    srand(233);
    unsigned char key;
    LPVOID encryptFileBuffer = NULL;
    encryptFileBuffer = FileBufferToImageBuffer((BYTE*)filebuffer, imgsize);
    for (i = 0; i < imgsize; i++)
    {
        key = rand();
        *((BYTE*)encryptFileBuffer + i) ^= key;
    }
    fwrite(encryptFileBuffer, imgsize, 1, c);
    free(filebuffer);
    free(encryptFileBuffer);
    free(shellbuffer);
    fclose(c);
    printf("done!\n");
    getchar();
    return 0;
}
LPVOID FileBufferToImageBuffer(BYTE* decodebuffer, DWORD& size)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader_LAST = NULL;


    pDosHeader = (PIMAGE_DOS_HEADER)decodebuffer;
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)decodebuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    pSectionHeader_LAST = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + (pPEHeader->NumberOfSections - 1) * 40);

    unsigned int fileLength = pSectionHeader_LAST->PointerToRawData + pSectionHeader_LAST->SizeOfRawData;
    size = pNTHeader->OptionalHeader.SizeOfImage;
    BYTE* pEncryptBuffer = (BYTE*)malloc(size);
    memset(pEncryptBuffer, 0, size);
    memcpy(pEncryptBuffer, decodebuffer, pNTHeader->OptionalHeader.SizeOfHeaders);
    int i;
    for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(pEncryptBuffer + pSectionHeader->VirtualAddress, decodebuffer + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
        pSectionHeader++;
    }


    return pEncryptBuffer;
}