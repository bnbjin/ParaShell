#include <windows.h>
#include "extradata.h"
#include "error.h"
#include "pe_utilities.h"


/*
	Description:	从文件中读取额外数据
	Parameters:		[in]HANDLE	_hFile
					[in]void*	_imagebase
					[out]void**  _pExtraData
					[out]unsigned long*	_ulExtraDataSize
*/
int ReadExtraData(HANDLE _hFile, void* _imagebase, void **_pExtraData, unsigned long *_ulExtraDataSize)
{
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)getSecHeader(_imagebase);

	DWORD dwSizeH = 0;
	DWORD dwSizeL = 0;
	unsigned long ulExtraDataSize = 0;
	void *pExtraData = 0;
	DWORD BytesRW;


	dwSizeL = GetFileSize(_hFile, &dwSizeH);

	ulExtraDataSize = dwSizeL - (pSecHeader->PointerToRawData + pSecHeader->SizeOfRawData);
	
	if (ulExtraDataSize>0)
	{
		pExtraData = new char[ulExtraDataSize];
		
		memset(pExtraData, 0, ulExtraDataSize);

		BOOL RetCode = ReadFile(_hFile, pExtraData, ulExtraDataSize, &BytesRW, NULL);
		if (FALSE == RetCode)
		{
			return ERR_INVALIDFILE;
		}
		// log : 额外数据读取完毕.
	}
	else
	{
		// log : 没有额外数据.
	}

	*_pExtraData = pExtraData;
	*_ulExtraDataSize = ulExtraDataSize;

	return ERR_SUCCESS;
}


/*
	Description:	把额外数据写入文件
*/
int WriteExtraData(HANDLE _hFile, void *_pExtraData, unsigned long ulExtraDataSize)
{
	DWORD BytesRW;

	SetFilePointer(_hFile, 0, NULL, FILE_END);	
	
	WriteFile(_hFile, _pExtraData, ulExtraDataSize, &BytesRW, NULL);
	
	// log : 写入额外数据完成
	return ERR_SUCCESS;
}