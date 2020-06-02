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
    const char srcaddr[] = "C:\\Users\\pisanbao\\Desktop\\encode_shell.exe";//src路径
    const char shelladdr[] = "C:\\Users\\pisanbao\\Desktop\\first.exe";//解壳shell路径
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
    b = fopen(shelladdr, "rb");
    fseek(b, 0, SEEK_END);
    unsigned long long shellsize = ftell(b);
    fseek(b, 0, SEEK_SET);
    DWORD* shellbuffer = (DWORD*)calloc(1, shellsize);
    fread(shellbuffer, shellsize, 1, b);
    fclose(b);
    //shell buffer get
    c = fopen("C:\\Users\\pisanbao\\Desktop\\shell.exe", "ab+");//最终成品
    IMAGE_DOS_HEADER * shelldosheader = (IMAGE_DOS_HEADER *)shellbuffer;
    IMAGE_NT_HEADERS* shellntheader = (IMAGE_NT_HEADERS*)((BYTE *)shellbuffer + shelldosheader->e_lfanew);
    IMAGE_SECTION_HEADER * shellsection = (IMAGE_SECTION_HEADER *)((BYTE*)shellbuffer + shelldosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + shellntheader->FileHeader.SizeOfOptionalHeader);
    for (i = 0; i < shellntheader->FileHeader.NumberOfSections; i++)//遍历节表直至最后一个节
        shellsection++;
    WORD temp = shelldosheader->e_lfanew;//这边保存一波ntheader偏移，因为要通过抹去dos stub来新增节
    DWORD tempsize = shellntheader->OptionalHeader.SizeOfHeaders;
    shelldosheader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    //shellntheader->FileHeader.NumberOfSections += 1;            //节表加一
    shellntheader->OptionalHeader.SizeOfImage += filentheader->OptionalHeader.SizeOfImage;
    strcpy((char *)shellsection->Name,".psb");
    shellsection->Misc.VirtualSize = filentheader->OptionalHeader.SizeOfImage;
    shellsection->VirtualAddress = shellntheader->OptionalHeader.SizeOfImage;
    shellsection->SizeOfRawData = filesize;
    shellsection->PointerToRawData = shellsize;
    shellsection->Characteristics = 0xe0500060;
    for (i = temp,j=0; i < tempsize; i++,j++)//循环抹去dos stub，因为会波及到sizeofheader所以这边提前保存了临时变量tempsize
    {
        *((BYTE*)shellbuffer + sizeof(IMAGE_DOS_HEADER)+j) = *((BYTE*)shellbuffer + i);
        *((BYTE*)shellbuffer + i) = 0;
    }
    fwrite((BYTE*)shellbuffer, shellsize, 1, c);
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