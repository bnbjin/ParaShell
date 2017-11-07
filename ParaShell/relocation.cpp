#include <windows.h>
#include "relocation.h"


/*
	Description:	重定位表变异处理函数
*/
bool MutateRelocation()
{
#ifdef __RELOCATION_SWITCH__
	PIMAGE_DATA_DIRECTORY		pRelocDir = NULL;
	PIMAGE_BASE_RELOCATION2		pBaseReloc = NULL;

	PCHAR						pRelocBufferMap = NULL;
	PCHAR						pData = NULL;
	UINT						nRelocSize = NULL;
	UINT						nSize = 0;
	UINT						nType = 0;
	UINT						nIndex = 0;
	UINT						nTemp = 0;
	UINT						nNewItemOffset = 0;
	UINT						nNewItemSize = 0;


	pRelocDir = &m_pntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	nRelocSize = pRelocDir->Size;
	pBaseReloc = (PIMAGE_BASE_RELOCATION2)RVAToPtr(pRelocDir->VirtualAddress);

	// 如果没有重定位数据，则直接返回
	if (pRelocDir->VirtualAddress == 0)
	{
		return TRUE;
	}
	//申请临时缓存空间
	pRelocBufferMap = new char[nRelocSize];
	if (pRelocBufferMap == NULL)
	{
		return FALSE;
	}
	ZeroMemory(pRelocBufferMap, nRelocSize);

	// 
	pData = pRelocBufferMap;

	while (pBaseReloc->VirtualAddress != 0)
	{
		nNewItemSize = (pBaseReloc->SizeOfBlock - 8) / 2;//保存新数据需要的字节长

		while (nNewItemSize != 0)
		{
			nType = pBaseReloc->TypeOffset[nIndex] >> 0x0c;//取type

			if (nType == 0x3)
			{
				//取出ItemOffset，加上本段重定位起始地址 ，减去nTemp,得到的值准备放到新重定位表结构中
				nNewItemOffset = ((pBaseReloc->TypeOffset[nIndex] & 0x0fff) + pBaseReloc->VirtualAddress) - nTemp;
				if (nNewItemOffset > 0xff)//如果是本段重定位数据第一项
				{
					*(BYTE *)(pData) = 3;
					pData += sizeof(BYTE);
					*(DWORD *)pData = (DWORD)(nNewItemOffset);
					pData += sizeof(DWORD);

				}
				else
				{
					*(BYTE *)(pData) = (BYTE)(nNewItemOffset);
					pData += sizeof(BYTE);
				}
				nTemp += nNewItemOffset;
			}
			nNewItemSize--;
			nIndex++;
		}

		nIndex = 0;
		pBaseReloc = (PIMAGE_BASE_RELOCATION2)((DWORD)pBaseReloc + pBaseReloc->SizeOfBlock);
	}

	memset((PCHAR)RVAToPtr(pRelocDir->VirtualAddress), 0, nRelocSize);
	memcpy((PCHAR)RVAToPtr(pRelocDir->VirtualAddress), pRelocBufferMap, nRelocSize);
	delete pRelocBufferMap;

#endif // __RELOCATION_SWITCH__
	return true;
}