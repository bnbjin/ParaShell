#ifndef __RELOCATION_H__
#define __RELOCATION_H__

#include <windows.h>
#include <vector>

#pragma pack(push)
#pragma pack(1)
#pragma warning(push)
#pragma warning(disable:4200)

/* 外壳中变异重定位表结构 */
struct Shell_MutatedRelocTab_NODE
{
	BYTE   type;
	DWORD  FirstTypeRVA;
	BYTE   Offset[];
};

#pragma pack(4)

/* 重定义原始重定位表结构 */
struct IMAGE_BASE_RELOCATION2
{
	DWORD   VirtualAddress;
	DWORD   SizeOfBlock;
	WORD    TypeOffset[];
};
// typedef IMAGE_BASE_RELOCATION2 UNALIGNED * PIMAGE_BASE_RELOCATION2;
typedef IMAGE_BASE_RELOCATION2 *PIMAGE_BASE_RELOCATION2;

#pragma warning(pop)
#pragma pack(pop)

struct MutatedRelocTabInfo
{
	void*	pMutatedRelocTab;
	DWORD	nMutatedRelocTab;

	/*
	TODO:
	1. 异常检测
	*/
	MutatedRelocTabInfo(DWORD sz) :
		pMutatedRelocTab(0), nMutatedRelocTab(sz)
	{
		pMutatedRelocTab = new char[nMutatedRelocTab];
		memset(pMutatedRelocTab, 0, nMutatedRelocTab);
	}

	~MutatedRelocTabInfo()
	{
		delete[] pMutatedRelocTab;
	}
};
//typedef MutatedRelocTabInfo *PMutatedRelocTabInfo;

class RelocTab
{
public:
	RelocTab(void* pImageBase);
	
	bool reset(void* pImageBase);

	bool dumpInShellForm(void* pMem);

	DWORD getMutatedRelocTabSizeInShell();

	bool clrOriginalRelocTab(void* pImageBase);

private:
	
	struct IMAGE_BASE_RELOCATION_MUTATED
	{
		BYTE   type;
		DWORD  FirstTypeRVA;
		std::vector<BYTE>   Offset;

		IMAGE_BASE_RELOCATION_MUTATED() :
			type(IMAGE_REL_BASED_ABSOLUTE),
			FirstTypeRVA(0),
			Offset()
		{}

		void clear()
		{
			type = IMAGE_REL_BASED_ABSOLUTE;
			FirstTypeRVA = 0;
			Offset.clear();
		}
	};

	bool marshallMutatedRelocTab(void* pImageBase);

	std::vector<IMAGE_BASE_RELOCATION_MUTATED> m_vMutatedRelocTab;
};

#endif // __RELOCATION_H__