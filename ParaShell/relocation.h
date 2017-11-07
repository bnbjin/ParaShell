#ifndef __RELOCATION_H__
#define __RELOCATION_H__

#include <windows.h>

//定义重定位表结构
typedef struct _IMAGE_BASE_RELOCATION2 {
	DWORD   VirtualAddress;
	DWORD   SizeOfBlock;
	WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION2;

// typedef IMAGE_BASE_RELOCATION2 UNALIGNED * PIMAGE_BASE_RELOCATION2;
typedef IMAGE_BASE_RELOCATION2 *PIMAGE_BASE_RELOCATION2;

//新构造的重定位表结构
/*	typedef struct _NEWIMAGE_BASE_RELOCATION {
BYTE   type;
DWORD  FirstTypeRVA;
BYTE   nNewItemOffset[1];
}
*/


/*
	Description:	重定位表变异处理函数
*/
bool MutateRelocation();

#endif // __RELOCATION_H__