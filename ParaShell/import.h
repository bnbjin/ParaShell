#ifndef __IMPORT_H__
#define __IMPORT_H__

#include <Windows.h>
#include <string>
#include <vector>

#pragma pack(push)
#pragma pack(1)
#pragma warning(push)
#pragma warning(disable:4200)

/* 外壳中变异输入表结构 */

struct Shell_MutatedImpTab_DLLNode_APINode
{
	union
	{
		DWORD Ordinal;
		BYTE ProcName[32];
	};
};

struct Shell_MutatedImpTab_DLLNode
{
	DWORD FirstThunk;
	BYTE DLLName[32];
	DWORD nFunc;
	Shell_MutatedImpTab_DLLNode_APINode FuncName[];
};

#pragma warning(pop)
#pragma pack(pop)

struct MutatedImpTabInfo
{
	void *pMutatedImpTab;
	unsigned long nMutatedImpTab;

	/*
	TODO:
	1. 异常检测
	*/
	MutatedImpTabInfo(unsigned long sz) :
		pMutatedImpTab(0), nMutatedImpTab(sz)
	{
		pMutatedImpTab = new char[nMutatedImpTab];
		memset(pMutatedImpTab, 0, nMutatedImpTab);
	}

	~MutatedImpTabInfo()
	{
		delete[] pMutatedImpTab;
	}
};
//typedef MutatedImpTabInfo *PMutatedImpTabInfo;

class ImpTab
{
public:
	/*
	description:	ctor,读取原始输入表，初始化变异输入表数据
	params:			[in]void* pImageBase
	Todo:
	*	1.输入检测，抛出异常
	*/
	ImpTab(void* pImageBase);

	/*
	description:	把变异输入表数据以外壳结构方式转存到内存中
	params:			[in]void* pMem
	returns:		bool
	*/
	bool dumpInShellForm(void* pMem);

	/*
	description:	重新读入去原始输入表数据，初始化变异输入表数据
	params:			[in]void* pImageBase
	returns:		bool
	*/
	bool reset(void* pImageBase);

	/*
	description:	获取变异输入表在外壳中大小
	returns:		大小
	*/
	DWORD getMutatedImpTabSizeInShell();

	/*
	description:	清楚原始输入表数据
	params:			[in]void* pImageBase
	returns:		bool
	*/
	bool clrOriginalImpTab(void* pImageBase);

private:
	struct MutatedImpTab_DLLNode_APINode
	{
		DWORD		Ordinal;
		std::string	APIName;

		MutatedImpTab_DLLNode_APINode() :
			Ordinal(0), APIName()
		{}

		void clear()
		{
			Ordinal = 0;
			APIName.clear();
		}

		bool isString()
		{
			return (0 == Ordinal && APIName.size());
		}
	};

	struct MutatedImpTab_DLLNode
	{
		DWORD	FirstThunk;
		std::string	DLLName;
		std::vector<MutatedImpTab_DLLNode_APINode>	vThunks;

		MutatedImpTab_DLLNode() :
			FirstThunk(0), DLLName(), vThunks()
		{}

		void clear()
		{
			FirstThunk = 0;
			DLLName.clear();
			vThunks.clear();
		}
	};
	typedef MutatedImpTab_DLLNode UNALIGNED *PMutatedImpTab_DLLNode;

	/*
	description:	读取输入表数据到容器(变异格式)
	params:			[in]void* pImageBase	// 文件内存基质指针
	returns:		bool
	*/
	bool marshallMutatedImpTab(void* pImageBase);
	
	std::vector<MutatedImpTab_DLLNode> m_vMutatedImpTab;
};

#endif // __IMPORT_H__
