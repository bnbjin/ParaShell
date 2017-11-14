#include "relocation.h"
#include "pe_utilities.h"

RelocTab::RelocTab(void* pImageBase) : m_vMutatedRelocTab()
{
	try
	{
		marshallMutatedRelocTab(pImageBase);
	}
	catch (std::exception& e)
	{
		e.what();
	}
}

bool RelocTab::reset(void* pImageBase)
{
	if (!pImageBase)
	{
		return false;
	}

	m_vMutatedRelocTab.clear();
	marshallMutatedRelocTab(pImageBase);

	return true;
}

bool RelocTab::dumpInShellForm(void* pMem)
{
	if (!pMem)
	{
		return false;
	}

	Shell_MutatedRelocTab_NODE* pData = (Shell_MutatedRelocTab_NODE*)pMem;

	for (auto iter = m_vMutatedRelocTab.begin(); iter != m_vMutatedRelocTab.end(); ++iter)
	{
		// type
		pData->type = iter->type;

		// FirstTypeRVA
		pData->FirstTypeRVA = iter->FirstTypeRVA;

		// Offset
		int i = 0;
		for (auto iterO = iter->Offset.begin(); iterO != iter->Offset.end(); ++i, ++iterO)
		{
			pData->Offset[i] = *iterO;
		}
		pData->Offset[i] = 0; // 空字段表示结束

		pData = (Shell_MutatedRelocTab_NODE*)&(pData->Offset[i + 1]);
	}

	return true;
}

DWORD RelocTab::getMutatedRelocTabSizeInShell()
{
	//nNewItemSize = (pBaseReloc->SizeOfBlock - 8) / 2;//保存新数据需要的字节长
	DWORD dwRes = 0;

	for (auto iter = m_vMutatedRelocTab.begin(); iter != m_vMutatedRelocTab.end(); iter++)
	{
		dwRes += sizeof(iter->type);
		dwRes += sizeof(iter->FirstTypeRVA);
		
		for (auto iterB = iter->Offset.begin(); iterB != iter->Offset.end(); ++iterB)
		{
			dwRes += sizeof(*iterB);
		}

		// 空字段表示块结束
		dwRes += sizeof(*(iter->Offset.begin()));
	}

	// 空块表示结束
	if (dwRes)
	{
		dwRes += sizeof(Shell_MutatedRelocTab_NODE::type)
			+ sizeof(Shell_MutatedRelocTab_NODE::FirstTypeRVA)
			+ sizeof(Shell_MutatedRelocTab_NODE::Offset[0]);
	}

	return dwRes;
}

bool RelocTab::clrOriginalRelocTab(void* pImageBase)
{
	if (!pImageBase)
	{
		return false;
	}

	return true;
}

bool RelocTab::marshallMutatedRelocTab(void* pImageBase)
{
	if (!pImageBase)
	{
		return false;
	}
	
	const PIMAGE_NT_HEADERS		pNTHeader = getNTHeader(pImageBase);
	PIMAGE_DATA_DIRECTORY		pRelocDir = &pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_BASE_RELOCATION2		pBaseReloc = (PIMAGE_BASE_RELOCATION2)RVAToPtr(pImageBase, pRelocDir->VirtualAddress);
	IMAGE_BASE_RELOCATION_MUTATED	tmpMutatedRelocTab_Node;

	if (0 == pRelocDir->VirtualAddress)
		throw std::exception("Relocation Table is empty.");

	while (pBaseReloc->VirtualAddress != 0)
	{
		DWORD i = 0;
		DWORD accumulation = 0;
		tmpMutatedRelocTab_Node.clear();
		
		// type
		tmpMutatedRelocTab_Node.type = pBaseReloc->TypeOffset[i] >> 0x0c;
		if (IMAGE_REL_BASED_HIGHLOW != tmpMutatedRelocTab_Node.type)
		{
			m_vMutatedRelocTab.clear();
			return false;
		}

		// FirstTypeRVA
		accumulation = pBaseReloc->VirtualAddress + (pBaseReloc->TypeOffset[i] & 0x0fff);
		tmpMutatedRelocTab_Node.FirstTypeRVA = accumulation;

		while (((DWORD)&(pBaseReloc->TypeOffset[i+1]) - (DWORD)pBaseReloc)
			< pBaseReloc->SizeOfBlock)
		{
			i++;
			WORD tmpType = pBaseReloc->TypeOffset[i] >> 0x0c;
			WORD tmpOffset = pBaseReloc->TypeOffset[i] & 0x0fff;

			if (IMAGE_REL_BASED_HIGHLOW == tmpType)
			{	// x86
				tmpMutatedRelocTab_Node.Offset.push_back(
					(WORD)((tmpOffset + pBaseReloc->VirtualAddress) - accumulation));
				accumulation = pBaseReloc->VirtualAddress + (pBaseReloc->TypeOffset[i] & 0x0fff);
			}
			else
			{
				continue;
			}
		}

		m_vMutatedRelocTab.push_back(tmpMutatedRelocTab_Node);
		pBaseReloc = (PIMAGE_BASE_RELOCATION2)((DWORD)pBaseReloc + pBaseReloc->SizeOfBlock);
	}

	return true;
}