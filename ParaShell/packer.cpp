#include <iostream>
#include <vector>
#include <Windows.h>
#include "packer.h"
#include "aplib\aplib.h"
#include "pe_utilities.h"
#include "shell.h"

#pragma comment(lib, "aplib\\aplib.lib")

/* implementation of pack_method_strategy */

pack_method_strategy* pack_method_strategy::factory(pack_type pt)
{
	pack_method_strategy* res = 0;

	switch (pt)
	{
	case pt_empty:
		break;
	case pt_xor:
		res = new pack_method_xor;
		break;
	case pt_aplib:
		res = new pack_method_ap;
		break;
	default:
		break;
	}

	return res;
}

/* implementation of pack_method_xor */

pack_method_xor::pack_method_xor() :
	pack_method_strategy(pt_xor), m_trait()
{}

bool pack_method_xor::set_traits(void* traits)
{
	if (!traits)
		return false;

	m_trait.key = ((trait*)traits)->key;

	return true;
}

unsigned long pack_method_xor::pack(
	void* psrc,
	unsigned long srclen,
	void* pdst,
	unsigned long dstlen)
{
	if (!psrc || !srclen || !pdst || !dstlen)
		return 0;

	if (get_packed_size(psrc, srclen) > dstlen)
		return 0;

	PBYTE psrc_data = (PBYTE)psrc;
	PBYTE pdst_data = (PBYTE)pdst;
	*pdst_data = m_trait.key;
	unsigned long i;
	for (i = 1; i <= srclen; ++i)
	{
		pdst_data[i] = psrc_data[i - 1] ^ m_trait.key;
	}

	return i;
}

unsigned long pack_method_xor::unpack(
	void* psrc,
	unsigned long srclen,
	void* pdst,
	unsigned long dstlen)
{
	if (!psrc || !srclen || !pdst || !dstlen)
		return 0;

	if (get_unpacked_size(psrc, srclen) > dstlen)
		return 0;

	PBYTE psrc_data = (PBYTE)psrc;
	PBYTE pdst_data = (PBYTE)pdst;
	BYTE  key = *psrc_data;
	++psrc_data;
	unsigned long i;
	for (i = 1; i < srclen; ++i)
	{
		pdst_data[i - 1] = psrc_data[i] ^ key;
	}

	return i-1;
}

unsigned long pack_method_xor::get_packed_size(void* pdata, unsigned long len)
{
	if (!pdata || !len)
		return 0;

	return len + 1;
}

unsigned long pack_method_xor::get_unpacked_size(void* pdata, unsigned long len)
{
	if (!pdata || !len)
		return 0;

	return len - 1;
}

/* implementation of pack_method_ap */

pack_method_ap::pack_method_ap() :
	pack_method_strategy(pt_aplib)
{}

bool pack_method_ap::set_traits(void* traits)
{
	return false;
}

unsigned long pack_method_ap::pack(
	void* psrc,
	unsigned long srclen,
	void* pdst,
	unsigned long dstlen)
{
	if (!psrc || !srclen || !pdst || !dstlen)
		return 0;

	if (get_packed_size(psrc, srclen) > dstlen)
		return 0;

	char* pworkmem = 0;
	unsigned int workmemsize = 0;
	unsigned int packedsize = 0;

	workmemsize = aP_workmem_size(srclen);
	pworkmem = new char[workmemsize];
	packedsize = aPsafe_pack(psrc, pdst, srclen, pworkmem, 0, 0);
	delete[]pworkmem;

	return packedsize;
}

unsigned long pack_method_ap::unpack(
	void* psrc,
	unsigned long srclen,
	void* pdst,
	unsigned long dstlen)
{
	if (!psrc || !srclen || !pdst || !dstlen)
		return 0;

	if (get_unpacked_size(psrc, srclen) > dstlen)
		return 0;

	unsigned int unpackedsize = 0;

	unpackedsize = aPsafe_depack(psrc, srclen, pdst, dstlen);
		
	return unpackedsize;
}

unsigned long pack_method_ap::get_packed_size(void* pdata, unsigned long len)
{
	if (!pdata || !len)
		return 0;

	return aP_max_packed_size(len);
}

unsigned long pack_method_ap::get_unpacked_size(void* pdata, unsigned long len)
{
	if (!pdata || !len)
		return 0;

	return aPsafe_get_orig_size(pdata);
}

/* implementation of packer */

packer::packer(pack_type pt) :
	m_method(pack_method_strategy::factory(pt))
{}

packer::~packer()
{
	pack_method_strategy::erase(m_method);
	m_method = 0;
}

bool packer::pack_shell(void* pImageBase)
{
	if (!pImageBase)
		return false;

	pack_method_xor::trait traits;
	traits.key = (BYTE)0x27;
	m_method->set_traits(&traits);
#ifdef _DEBUG
	std::cout << "packing type: " << m_method->get_type() << std::endl;
	std::cout << "packing trait: " << std::hex << traits.key << std::endl;
#endif 

	/*  压缩第二段shell(Luanch)  */
	PIMAGE_NT_HEADERS pNTHeader = getNTHeader(pImageBase);
	PIMAGE_SECTION_HEADER pLastSection = getLastSecHeader(pImageBase);
	void *pLuanch = RVAToPtr(pImageBase, pLastSection->VirtualAddress) \
		+ (DWORD)(&Label_Luanch_Start) \
		- (DWORD)(&Label_Shell_Start);
	DWORD nLuanchSize = (DWORD)(&Label_Luanch_End) - (DWORD)(&Label_Luanch_Start);
	
	unsigned long Luanch_maxpackedsize = m_method->get_packed_size(pLuanch, nLuanchSize);
	void* tmpblock = new char[Luanch_maxpackedsize];
	unsigned long Luanch_packedsize = m_method->pack(pLuanch, nLuanchSize, tmpblock, Luanch_maxpackedsize);
	
	memset(pLuanch, 0, nLuanchSize);
	memcpy(pLuanch, tmpblock, Luanch_packedsize);
	delete[]tmpblock;
	
	/* 压缩完成，把相关数据写入映像 */
	PInduction_Data pInduction_Data = (PInduction_Data) \
		(RVAToPtr(pImageBase, pLastSection->VirtualAddress) \
			+ (DWORD)(&Label_Induction_Data_Start) \
			- (DWORD)(&Label_Shell_Start));
	pInduction_Data->LuanchPNode.Type = m_method->get_type();
	pInduction_Data->LuanchPNode.PackedRVA = pInduction_Data->LuanchPNode.OriginalRVA;
	pInduction_Data->LuanchPNode.PackedSize = Luanch_packedsize;

	/*  修正映像大小与相关字段  */
	// TODO：

	return true;
}