#ifndef __PE_UTILITIES_H__
#define __PE_UTILITIES_H__

#include <windows.h>
#include <vector>

/*
	Description:	取整对齐函数
*/
UINT AlignSize(UINT nSize, UINT nAlign);


/*
	Description:	RVA->指向堆中对应位置的指针
*/
char* RVAToPtr(const void* imagebase, const unsigned long dwRVA);


/*
	Description:	获取NT头指针
*/
PIMAGE_NT_HEADERS getNTHeader(const void* imagebase);


/*
	Description:	获取section表指针
*/
PIMAGE_SECTION_HEADER getSecHeader(const void* _imagebase);


/*
	Description:	获取最后一个区块表项指针
*/
PIMAGE_SECTION_HEADER getLastSecHeader(const void* _pImageBase);


/*
	Description:	搜索并去掉尾部无用的零字节，重新计算区块的大小
*/
unsigned int CalcMinSizeOfData(char* pSectionData, const unsigned int nSectionSize);


/*
	Description:	判断当前区块数据能否被压缩
*/
bool IsSectionPackable(PIMAGE_SECTION_HEADER pSecHeader);


/*
	Description:	备份文件
*/
int BackUpFile(TCHAR *szFilePath);


/*
	Description:	获取DOS头大小
*/
unsigned int GetDosHeaderSize(void* _pImageBase);


/*
	Description:	获取NT头大小
*/
unsigned int GetNTHeaderSize(void* _pImageBase);


/*
	Description:	在区块表最后添加新区快,new申请新区快内存，需要调用者delete
*/
unsigned int CreateNewSection(void* _pImageBase, const unsigned long _secsize, void **_ppNewSection);


/*
	Description:	把输入的内存块融合到一起
*/
void* MergeMemBlock(void* _pImageBase, void* _pShellSection);


/*
	Description:	把原输入表所在区块属性设为可写
*/
int	MakeOriginalImportSecWritable(void *_pImageBase);

#endif //__PE_UTILITIES_H__
