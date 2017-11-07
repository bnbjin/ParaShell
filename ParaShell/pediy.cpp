#include <windows.h>
#include "pediy.h"
#include "pe_utilities.h"
#include "error.h"
#include "config.h"
#include "relocation.h"
#include "import.h"
#include "section.h"
#include "extradata.h"
#include "packing.h"
#include "shell.h"


/*
	Description:	处理数据流程
	RetValue:		ERR_SUCCESS
					ERR_UNKNOWN
*/
int ProtTheFile(TCHAR *szFilePath)
{
	HANDLE hFile;
	void* pImageBase = 0;
	void* pExtraData = 0;
	void* pShellSection = 0;
	unsigned long ulExtraDataSize = 0;

	try
	{
		ISWORKING = true;
		
		/*  创建备分文件  */
		if (ISCREATEBAK)
		{
			BackUpFile(szFilePath);
		}

		// 	读取文件到堆中
		ReadFileToHeap(szFilePath, &hFile, &pImageBase);

		// FixPEHeader(pimagebase);
		
		/*  额外数据读取  */
		if (ISSAVEDATA)
		{
			ReadExtraData(hFile, pImageBase, &pExtraData, &ulExtraDataSize);
		}

		CloseHandle(hFile);

		// log : 文件读入完毕


		/*  处理重定位数据  */
		if (ISMUTATERELOC)
		{	 
			MutateRelocation();
		}


		/*  输入表变异  */
		MutateImportInfo MImpInfo = {0};
		if (ISMUTATEIMPORT)
		{
			MutateImport(pImageBase, &MImpInfo);
		}


		/*  合并区段  */
		if (ISMERGESECTION)
		{
			MergeSection();
		}


		/* */
		hFile = CreateFile(
			szFilePath,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return  FALSE;
		}


		/*  添加shell段  */
		std::vector<DataToShellNode> vDTS;
		DataToShellNode tmpDTSN;
		if (ISMUTATEIMPORT)
		{
			tmpDTSN.DataType = ShellDataType::MImp;
			tmpDTSN.pData = MImpInfo.pMutateImport;
			tmpDTSN.nData = MImpInfo.nMutateImport;
			vDTS.push_back(tmpDTSN);
		}
		ImployShell(pImageBase, vDTS, &pShellSection);


		/*  融合内存块 */
		void* pNewImage = MergeMemBlock(pImageBase, pShellSection);
		delete[]pImageBase;
		pImageBase = pNewImage;
		pNewImage = 0;


		/*  压缩区块数据  */
		PackFile(pImageBase);
	

		/*  把堆中数据写入文件  */
		// TODO : mergememblock
		WriteHeapToFile(hFile, pImageBase);


		/*  写入额外数据  */
		if (ISSAVEDATA)
		{
			WriteExtraData(hFile, pExtraData, ulExtraDataSize);
		}

		/*  加密完成,清理  */
		if (0 != pImageBase) delete []pImageBase;
		if (0 != pShellSection) delete []pShellSection;
		if (0 != MImpInfo.pMutateImport)	delete[]MImpInfo.pMutateImport;
		//if (ISPACKRES)	delete []pMapOfPackRes;
		if (0 != pExtraData)	delete []pExtraData;

		CloseHandle(hFile);

		ISWORKING = false;
	}
	catch (...)
	{
		// TODO: 处理异常的堆栈平衡吗？
		MessageBox(NULL, TEXT("处理文件流程中出现错误."), NULL, 0);
		return ERR_UNKNOWN;
	}

	return ERR_SUCCESS;
}


/*
Description:	判断文件是否为有效PE文件
RetValue:		ERR_INVALIDFILE
ERR_SUCCESS
*/
int IsPEFile(TCHAR *szFilePath)
{

	DWORD					fileSize;
	HANDLE					hMapping;
	LPVOID					pFileMap;
	PIMAGE_DOS_HEADER	    pDosHeader = NULL;
	PIMAGE_NT_HEADERS       pNtHeader = NULL;
	PIMAGE_FILE_HEADER      pFilHeader = NULL;
	PIMAGE_OPTIONAL_HEADER  pOptHeader = NULL;
	PIMAGE_SECTION_HEADER   pSecHeader = NULL;


	//打开文件
	HANDLE hFile = CreateFile(
		szFilePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return	ERR_INVALIDFILE;
	}

	//获得文件长度 :
	fileSize = GetFileSize(hFile, NULL);
	if (fileSize == 0xFFFFFFFF)
	{
		return	ERR_INVALIDFILE;
	}

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapping)
	{
		CloseHandle(hFile);

		return ERR_INVALIDFILE;
	}

	pFileMap = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pFileMap)
	{
		CloseHandle(hMapping);
		CloseHandle(hFile);

		return ERR_INVALIDFILE;
	}

	// 检验DOS标志
	pDosHeader = (PIMAGE_DOS_HEADER)pFileMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return ERR_INVALIDFILE;
	}

	// 检验NT标志
	pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return ERR_INVALIDFILE;
	}

	// 是否只有一个区块
	pFilHeader = &pNtHeader->FileHeader;
	if (pFilHeader->NumberOfSections == 1)
	{
		return ERR_INVALIDFILE;
	}

	pOptHeader = &pNtHeader->OptionalHeader;//得到IMAGE_OPTIONAL_HEADER结构指针的函数
											// pOptHeader->AddressOfEntryPoint;

											//得到第一个区块的起始地址  
	pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
	pSecHeader++;//得到第二个区块的起始地址
				 // 如果 程序入口点地址 比 第二个区块起始地址 大
	if ((pOptHeader->AddressOfEntryPoint) > (pSecHeader->VirtualAddress)) {
		return ERR_INVALIDFILE;
	}

	if (((pFilHeader->Characteristics) & IMAGE_FILE_DLL) != 0)
	{
		// DLL
	}
	else
	{
		// EXE
	}

	UnmapViewOfFile(pFileMap);
	CloseHandle(hMapping);
	CloseHandle(hFile);

	return ERR_SUCCESS;
}


/*
	Description:	读取目标文件到堆中，进程影像方式
	Parameters:		TCHAR *szFilePath	in:文件路径
					HANDLE *hFile		out:
					void **imagebase	out:
*/
int ReadFileToHeap(TCHAR *szFilePath, HANDLE *_hfile, void **_pimagebase)
{
	HANDLE hFile;
	IMAGE_DOS_HEADER dosheader;
	IMAGE_NT_HEADERS ntheader;
	PIMAGE_SECTION_HEADER psecheader;
	DWORD	RWbytes;
	unsigned long imagesize_fix;
	void* pimagebase;
	BOOL bRetCode;

	hFile = CreateFile(
		szFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return  FALSE;
	}

	// 输出第二个参数
	*_hfile = hFile;

	/*  读取文件头获取文件信息  */

	// 读DOS头 
	bRetCode = ReadFile(hFile, &dosheader, sizeof(dosheader), &RWbytes, NULL);
	if (FALSE == bRetCode)
	{
		return ERR_INVALIDFILE;
	}

	// 定位到PE头起始处e_lfanew
	SetFilePointer(hFile, dosheader.e_lfanew, NULL, FILE_BEGIN);

	// 读出PE头
	bRetCode = ReadFile(hFile, &ntheader, sizeof(ntheader), &RWbytes, NULL);
	if (FALSE == bRetCode)
	{
		return ERR_INVALIDFILE;
	}

	// 修正可能存在的映象大小没有对齐的情况
	imagesize_fix = AlignSize(ntheader.OptionalHeader.SizeOfImage, ntheader.OptionalHeader.SectionAlignment);

	// 申请内存用于保存映象
	pimagebase = new unsigned char[imagesize_fix];
	if (pimagebase == NULL)
	{
		// log : 错误!内存不足！
		return ERR_OUTOFMEM;
	}
	*_pimagebase = pimagebase;

	memset(pimagebase, 0, imagesize_fix);

	// 首先定位并读PE文件头到内存中
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	bRetCode = ReadFile(hFile, pimagebase, ntheader.OptionalHeader.SizeOfHeaders, &RWbytes, NULL);
	if (FALSE == bRetCode)
	{
		return ERR_INVALIDFILE;
	}

	// 循环依次读出区块数据到映象中的虚拟地址处
	psecheader = getSecHeader(pimagebase);
	for (unsigned int index = 0; 
		index < ntheader.FileHeader.NumberOfSections; 
		++index, ++psecheader)
	{
		// 定位到SECTION数据起始处
		SetFilePointer(hFile, psecheader->PointerToRawData, NULL, FILE_BEGIN);

		// 读SECTION数据到映象中
		bRetCode = ReadFile(
			hFile, 
			&((char*)pimagebase)[psecheader->VirtualAddress], 
			psecheader->SizeOfRawData, &RWbytes, 
			NULL);
		if (FALSE == bRetCode)
		{
			return ERR_INVALIDFILE;
		}
	}

	return ERR_SUCCESS;
}


/*
	Description:	把数据从堆写入到文件
	// 注：堆中是按进程内存映射方式存储的，写入时需要注意区块地址
*/
int WriteHeapToFile(HANDLE _hFile, void* _pImageBase)
{
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)getNTHeader(_pImageBase);
	DWORD BytesRW;


	// 写入PE头
	SetFilePointer(_hFile, 0, NULL, FILE_BEGIN);
	WriteFile(_hFile, _pImageBase, pNTHeader->OptionalHeader.SizeOfHeaders, &BytesRW, NULL);

	// 写入各区块
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)getSecHeader(_pImageBase);
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, pSecHeader++)
	{
		SetFilePointer(_hFile, pSecHeader->PointerToRawData, 0, FILE_BEGIN);
		WriteFile(_hFile, RVAToPtr(_pImageBase, pSecHeader->VirtualAddress), pSecHeader->SizeOfRawData, &BytesRW, NULL);
	}

	return ERR_SUCCESS;
}


/*
	Description:	修正PE头信息
*/
int FixPEHeader(void *_pimagebase)
{
	PIMAGE_DOS_HEADER pdosheader = (PIMAGE_DOS_HEADER)_pimagebase;;
	PIMAGE_NT_HEADERS pntheader = (PIMAGE_NT_HEADERS)getNTHeader(_pimagebase);
	PIMAGE_SECTION_HEADER psecheader = (PIMAGE_SECTION_HEADER)getSecHeader(_pimagebase);
	PIMAGE_SECTION_HEADER psecheader_iterator;

	unsigned long sectionnum = pntheader->FileHeader.NumberOfSections;
	unsigned int index;

	// 对存储在堆中的区块表数据进行修正
	// 每个区块表中的SizeOfRawData, VirtualSize
	for (index = 0, psecheader_iterator = psecheader; index < sectionnum; ++index, ++psecheader_iterator)
	{
		// 修正可能存在的对齐问题
		psecheader_iterator->SizeOfRawData = AlignSize(psecheader_iterator->SizeOfRawData, pntheader->OptionalHeader.FileAlignment);
		psecheader_iterator->Misc.VirtualSize = AlignSize(psecheader_iterator->Misc.VirtualSize, pntheader->OptionalHeader.SectionAlignment);
	}

	return ERR_SUCCESS;
}


