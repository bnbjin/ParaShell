#ifndef __SHELL_H__
#define __SHELL_H__

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

struct Induction_Data 
{
	DWORD	nShellStep;
	DWORD	LuanchBase;			// RVA
	DWORD   LuanchAllocBase;
	DWORD   ImageBase;
	DWORD	nLuanchOriginalSize;
	DWORD   nLuanchPackSize;
	BYTE	szVirtualAlloc[13];
	DWORD	VirtualAllocAddr;
	BYTE	TlsTable[18];
};

struct Luanch_Data
{
	DWORD	OEP;
	DWORD	IsMutateImpTable;
	DWORD	MutateImpTableAddr;		// RVA to shell
	DWORD	OriginalImpTableAddr;
	DWORD	IsDLL;
	DWORD	OriginalRelocAddr;
	BYTE	SectionPackInfo[0xa0];
};
#pragma pack(pop)

typedef Induction_Import* UNALIGNED PInduction_Import;
typedef Induction_Data* UNALIGNED PInduction_Data;
typedef Luanch_Data* UNALIGNED PLuanch_Data;


// 需要写入shell的数据的类型
enum ShellDataType
{
	MImp,
	MReloc,
	MTLS,
	MOthers
};

// 需要写入shell的数据信息
struct DataToShellNode
{
	void *pData;
	unsigned long nData;
	ShellDataType DataType;
};


/*
	Description:	安置shell区块,_pShellSection需要调用者delete
*/
int ImployShell(void* _pImageBase, std::vector<DataToShellNode> &_rvDataToShell, void **_ppShellSection);


#endif // __SEHLL_H__
