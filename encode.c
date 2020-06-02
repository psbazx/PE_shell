#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>

int main()
{
    FILE* a;
    FILE* b;
    FILE* c;
    int i,j;
    const char shelladdr[] = "C:\\Users\\pisanbao\\Desktop\\encode_shell.exe";//shell路径
    const char srcaddr[] = "C:\\Users\\pisanbao\\Desktop\\first.exe";//src路径
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
    if (tempsection->Misc.VirtualSize % 0x1000)
    {
        temptemp = ((tempsection->Misc.VirtualSize / 0x1000) + 1) * 0x1000;
    }
    else
    {
        temptemp = tempsection->Misc.VirtualSize;
    }
    unsigned long long realsize = tempsection->SizeOfRawData + tempsection->PointerToRawData;
    shellsection->Misc.VirtualSize = filesize;
    shellsection->VirtualAddress = tempsection->VirtualAddress + temptemp;
    shellsection->SizeOfRawData = count1;
    shellsection->PointerToRawData = realsize;//这边踩坑了，有些编译器会在最后节后面加东西导致文件不对齐
    shellsection->Characteristics = 0xe0500060;
    shellntheader->FileHeader.NumberOfSections += 1;        //节数+1  
    shellntheader->OptionalHeader.SizeOfImage = shellsection->VirtualAddress + realimage;
    for (i = temp,j=0; i < tempsize; i++,j++)
    {
        *((BYTE*)shellbuffer + sizeof(IMAGE_DOS_HEADER)+j) = *((BYTE*)shellbuffer + i);
        *((BYTE*)shellbuffer + i) = 0;
    }
    fwrite((BYTE*)shellbuffer, realsize, 1, c);
    //新增节完成
    //加密pe最后填充
    /*
    for (i = 0; i < filesize; i++)//这边加密随便写，为了方便暂时只写个简单xor，当然可以根据需要自己来整
        *((BYTE*)filebuffer + i) ^= 0x32;
        */
    fwrite(filebuffer, filesize, 1, c);
    free(filebuffer);
    free(shellbuffer);
    fclose(c);
    printf("done!\n");
    getchar();
    return 0;
}
