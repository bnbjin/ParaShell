#ifndef __PEDIY_H__
#define __PEDIY_H__

#include <windows.h>


/*
	Description:	处理数据流程
	RetValue:		ERR_SUCCESS
					ERR_UNKNOWN
*/
int ProtTheFile(TCHAR *szFilePath);


/*
	Description:	判断文件是否为有效PE文件
	RetValue:		ERR_INVALIDFILE
					ERR_SUCCESS
*/
int IsPEFile(TCHAR *szFilePath);


/*
	Description:	读取目标文件到堆中，进程影像方式
	Parameters:		TCHAR *szFilePath	in:文件路径
	HANDLE *hFile		out:
	void **imagebase	out:
*/
int ReadFileToHeap(TCHAR *szFilePath, HANDLE *_hfile, void **_pimagebase);


/*
	Description:	把数据从堆写入到文件
*/
int WriteHeapToFile(HANDLE _hFile, void* _pImageBase);


/*
	Description:	修正PE头信息
*/
int FixPEHeader(void *_pimagebase);

#endif // __PEDIY_H__
