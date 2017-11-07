#ifndef __IMPORT_H__
#define __IMPORT_H__

#include <Windows.h>
#include <string>
#include <vector>

#pragma push(pack)
#pragma pack(1)

struct shell_MutatedImpTab_DLLNode_APINode
{};

#pragma pop(pack)

class ImpTab
{
public:
	ImpTab();


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

	struct MutateImportInfo
	{
		void *pMutateImport;
		unsigned long nMutateImport;
	};
	typedef MutateImportInfo *PMutateImportInfo;

	/*
	description:	输入表变异处理
	returns:		ERR_SUCCESS
	*/
	int MutateImport(void *_pImageBase, PMutateImportInfo _pMutateImportInfo);

	/*
		Description:	计算变异输入表存放需要的大小
	*/
	unsigned long CalcMutateImpSize(std::vector<MutatedImpTab_DLLNode> &_rvMuateImport);
};

#endif // __IMPORT_H__
