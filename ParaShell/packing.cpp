#include <list>
#include <Windows.h>
#include "packing.h"
#include "aplib\aplib.h"
#include "pe_utilities.h"
#include "shell.h"

#pragma comment (lib, "aplib\\aplib.lib")


/*
	Description :	压缩文件映像中的内容
					默认把最后一个区块视为shell
					默认把变异数据放到shell中
*/
int PackFile(void *_pImageBase, void *_pMutateImp, void *_pMutateReloc, void *_pMutateTLS)
{
	std::list<PackInfoNode> lstPackInfoTable;


	/*  处理变异数据  */
	if (0 != _pMutateImp)
	{
		// TODO:
	}

	if (0 != _pMutateReloc)
	{
		// TODO:
	}

	if (0 != _pMutateTLS)
	{
		// TODO:
	}


	/*  压缩第二段shell(Luanch)  */
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(_pImageBase);
	PIMAGE_SECTION_HEADER pLastSection = getLastSecHeader(_pImageBase);
	void *pLuanch = RVAToPtr(_pImageBase, pLastSection->VirtualAddress) \
		+ (unsigned long)(&Label_Luanch_Start) \
		- (unsigned long)(&Label_Shell_Start);
	unsigned long nLuanchSize = (unsigned long)(&Label_Luanch_End) - (unsigned long)(&Label_Luanch_Start);
	PackInfoNode PIN;
	memset(&PIN, 0, sizeof(PackInfoNode));
	PIN.OriginalOffset = pLuanch;
	PIN.OriginalSize = nLuanchSize;
	PIN.PackedOffset = new char[nLuanchSize];
	PackData(&PIN);
	/* 压缩完成，把相关数据写入映像 */
	memset(pLuanch, 0, nLuanchSize);
	memcpy(pLuanch, PIN.PackedOffset, PIN.PackedSize);
	PInduction_Data pInduction_Data = (PInduction_Data) \
		(RVAToPtr(_pImageBase, pLastSection->VirtualAddress) \
			+ (unsigned long)(&Label_Induction_Data_Start) \
			- (unsigned long)(&Label_Shell_Start));
	pInduction_Data->nLuanchOriginalSize = nLuanchSize;
	pInduction_Data->nLuanchPackSize = PIN.PackedSize;
	delete[]PIN.PackedOffset;


	/*  修正映像大小与相关字段  */
	// TODO：

	
	return ERR_SUCCESS;
}


/* 
	Description:	调用aplib压缩引擎压缩数据                                   
*/
int PackData(PackInfoNode *_pPIN)
{
	char* pworkmem = 0;
	unsigned int workmemsize = 0;

	try
	{
		// 计算工作空间大小
		workmemsize = aP_workmem_size(_pPIN->OriginalSize);

		// 申请工作空间
		pworkmem = new char[workmemsize];

		// 对原始数据进行压缩
		_pPIN->PackedSize = aP_pack(_pPIN->OriginalOffset, _pPIN->PackedOffset, _pPIN->OriginalSize, pworkmem, 0, 0);

		delete[]pworkmem;
	}
	catch (...)
	{
		// log : "未知异常."
		return ERR_UNKNOWN;

	}

	return ERR_SUCCESS;
}
