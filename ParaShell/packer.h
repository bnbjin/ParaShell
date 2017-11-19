#pragma once

#include <exception>
#include <Windows.h>

#pragma pack(push)
#pragma pack(1)
struct PackInfoNode
{	
	DWORD	type;
	DWORD	OriginalOffset;	// RVA
	DWORD	OriginalSize;
	DWORD	PackedOffset;	// RVA
	DWORD	PackedSize;
	DWORD	AllocatedAddr;
};
#pragma pack(pop)

enum pack_type
{
	pt_empty,
	pt_xor,
	pt_aplib,
};

class pack_method_strategy
{
public:
	pack_method_strategy(pack_type pt) : m_type(pt) {}

	virtual bool set_traits(void* traits) = 0;
	
	virtual unsigned long pack(
		void* psrc,
		unsigned long srclen,
		void* pdst,
		unsigned long dstlen) = 0;
	
	virtual unsigned long unpack(
		void* psrc,
		unsigned long srclen,
		void* pdst,
		unsigned long dstlen) = 0;
	
	virtual unsigned long get_packed_size(void* pData, unsigned long len) = 0;

	virtual unsigned long get_unpacked_size(void* pdata, unsigned long len) = 0;
	
	int get_type() { return (int)m_type; }

	static pack_method_strategy* factory(pack_type pt);
	
	static void erase(pack_method_strategy* obj) { delete obj; }

protected:
	pack_type m_type;
};

class pack_method_xor : public pack_method_strategy
{
public:
	struct trait
	{
		BYTE key;
		
		trait() : key(0) {}

		void clr()
		{
			key = 0;
		}
	};

public:
	pack_method_xor();

	virtual bool set_traits(void* traits);
	
	virtual unsigned long pack(
		void* psrc,
		unsigned long srclen,
		void* pdst,
		unsigned long dstlen);
	
	virtual unsigned long unpack(
		void* psrc,
		unsigned long srclen,
		void* pdst,
		unsigned long dstlen);
	
	virtual unsigned long get_packed_size(void* pData, unsigned long len);

	virtual unsigned long get_unpacked_size(void* pdata, unsigned long len);

private:
	trait	m_trait;
};

class pack_method_ap : public pack_method_strategy
{
public:
	pack_method_ap();

	virtual bool set_traits(void* traits);
	
	virtual unsigned long pack(
		void* psrc,
		unsigned long srclen,
		void* pdst,
		unsigned long dstlen);
	
	virtual unsigned long unpack(
		void* psrc,
		unsigned long srclen,
		void* pdst,
		unsigned long dstlen);
	
	virtual unsigned long get_packed_size(void* pdata, unsigned long len);

	virtual unsigned long get_unpacked_size(void* pdata, unsigned long len);
};



class packer
{
public:
	packer(pack_type pt);

	~packer();
	
	bool pack_shell(void* pImageBase);

private:
	pack_method_strategy* m_method;
};