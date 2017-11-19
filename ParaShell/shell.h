#pragma once

#include <windows.h>
#include <vector>

/*  shell中的变量  */
extern "C"	DWORD	Label_Shell_Start;
extern "C"	DWORD	Label_Shell_End;
extern "C"	DWORD	Label_Induction_Start;
extern "C"  DWORD   Label_Induction_End;
extern "C"	DWORD	Label_Induction_Data_Start;
extern "C"	DWORD	Label_Induction_Data_End;
extern "C"  DWORD	Label_Induction_Import_Start;
extern "C"	DWORD	Label_Induction_Import_End;
extern "C"	DWORD	Label_Luanch_Start;
extern "C"	DWORD	Label_Luanch_End;
extern "C"	DWORD	Lable_Luanch_Data_Start;
extern "C"	DWORD	Lable_Luanch_Data_End;


#pragma pack(push)
#pragma pack(1)
struct Induction_Import
{
	IMAGE_IMPORT_DESCRIPTOR	ImpD[2];
	IMAGE_THUNK_DATA Thunk[4];
};

struct Shell_Pack_Info_Node
{
	DWORD	Type;
	DWORD	OriginalRVA;
	DWORD	OriginalSize;
	DWORD	PackedRVA;
	DWORD	PackedSize;
	DWORD	TempMemBlock;
};

struct Induction_Data 
{
	DWORD	nShellStep;
	//DWORD	LuanchBase;
	//DWORD   LuanchAllocatedBase;
	DWORD   ImageBase;
	//DWORD	nLuanchOriginalSize;
	//DWORD   nLuanchPackSize;
	Shell_Pack_Info_Node LuanchPNode;
	BYTE	szVirtualAlloc[13];
	DWORD	VirtualAllocAddr;
	BYTE	TlsTable[18];
};

#define MUTATEDINFO_BITSEPERITEM 1
struct MutatedInfo
{
	DWORD	ImpTab : MUTATEDINFO_BITSEPERITEM, \
			RelocTab : MUTATEDINFO_BITSEPERITEM; \
};

enum MInfo_ImpTabType
{
	MIITT_NOTHING,	// 无任何操作
	MIITT_MUTATED,	// 变异
};

enum MInfo_RelocTabType
{
	MIRTT_NOTHING,
	MIRTT_MUTATED,
};

// 需要写入shell的数据的类型
enum ShellDataType
{
	MImp,
	MReloc,
	MOthers
};

struct ShellDataNode
{
	DWORD	Type;	// ShellDataType
	DWORD	OriginalAddr;	// RVA to ImageBase
	DWORD	MutatedAddr;	// RVA to ImageBase
};

struct Luanch_Data
{
	DWORD	OEP;
	DWORD	OriginalImageBase;
	DWORD	IsDLL;
	MutatedInfo		MInfo;			
	ShellDataNode	Nodes[8 * sizeof(MutatedInfo) / MUTATEDINFO_BITSEPERITEM];
	BYTE	SectionPackInfo[0xa0];
};

#pragma pack(pop)

typedef Induction_Import* UNALIGNED PInduction_Import;
typedef Induction_Data* UNALIGNED PInduction_Data;
typedef Luanch_Data* UNALIGNED PLuanch_Data;

// 需要写入shell的数据信息
struct DataToShellNode
{
	void* pData;
	DWORD nData;
	ShellDataType DataType;
};

/*
	Description:	安置shell区块,_pShellSection需要调用者delete
*/
int buildShell(void* _pImageBase, std::vector<DataToShellNode> &_rvDataToShell, void **_ppShellSection);

/*
description:	修正伪装输入表字段
params:			[in]void* pImageBase
*				[in + out]void* pSecShell
returns:		bool
*/
bool fixFakedImpTabItem(void* pImageBase, void* pSecShell);

/*
description:	修正外壳数据字段
params:			[in]void* pImageBase
*				[in + out]void* pSecShell
returns:		bool
*/
bool fixShellData(void* pImageBase, void* pSecShell);

/*
description:	把输入表信息安置到被加壳程序中
params:			[in]void* pImageBase
*				[in]const void* pImpTabData
*				[in]const DWORD nImpTabData
*				[in + out]void* pSecShell
*				[in + out]DWORD Offset
returns:		bool
*/
bool buildImpTab(
	void* pImageBase,
	const void* pImpTabData,
	const DWORD nImpTabData,
	void* pSecShell,
	DWORD Offset);

/*
description:	把重定位表信息安置到被加壳程序中
params:			[in]void* pImageBase
*				[in]const void* pRelocTabData
*				[in]const DWORD nRelocTabData
*				[in + out]void* pSecShell
*				[in + out]DWORD Offset
returns:		bool
*/
bool buildRelocTab(
	void* pImageBase,
	const void* pRelocTabData,
	const DWORD nRelocTabData,
	void* pSecShell,
	DWORD Offset);