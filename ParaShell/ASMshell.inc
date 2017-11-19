IFNDEF __ASMSHELL_INC__
__ASMSHELL_INC__	equ	<1>
;__ASMSHELL_DEBUG__	equ <1>

PUBLIC  C	Label_Shell_Start
PUBLIC  C   Label_Shell_End
PUBLIC	C	Label_Induction_Start
PUBLIC	C	Label_Induction_End
PUBLIC	C	Label_Induction_Data_Start
PUBLIC  C   Label_Induction_Data_End
PUBLIC  C 	Label_Induction_Import_Start
PUBLIC  C 	Label_Induction_Import_End
PUBLIC	C	Label_Luanch_Start
PUBLIC	C	Label_Luanch_End
PUBLIC	C	Lable_Luanch_Data_Start
PUBLIC 	C 	Lable_Luanch_Data_End
;PUBLIC	C	TlsTable
;PUBLIC	C	RelocBaseBegin

; error types
ERR_INVALIDPARAMS	EQU -2
ERR_FAILED			EQU -1
ERR_SUCCEEDED		EQU	0

MY_IMAGE_IMPORT_DESCRIPTOR STRUCT    
	UNION Misc
		Characteristics 	DD	?	; 0 for terminating null import descriptor
		OriginalFirstThunk 	DD	?	; RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	ENDS
	TimeDateStamp	DD	?
    ForwarderChain	DD	?
	DLLName			DD	?
	FirstThunk		DD	?            ; RVA to IAT
MY_IMAGE_IMPORT_DESCRIPTOR ENDS

MY_IMAGE_IMPORT_THUNK STRUCT
	UNION u1
		Ordinal		DWORD	?
		FuncAddr	DWORD	?
	ENDS
MY_IMAGE_IMPORT_THUNK ENDS


MY_IMAGE_IMPORT_BY_NAME STRUCT
	Hint		DW	?
	FuncName	DB	32 DUP (?)
MY_IMAGE_IMPORT_BY_NAME ENDS

; packer type
PT_Nothing	EQU	0h
PT_Xor		EQU 1h
PT_AP		EQU 2h

SHELL_PACK_INFO_NODE STRUCT
	Type_			DD	0
	OriginalOffset	DD	0
	OriginalSize	DD	0
	PackedOffset	DD	0
	PackedSize		DD	0
	AllocatedAddr	DD	0
SHELL_PACK_INFO_NODE ENDS

INDUCTION_DATA STRUCT
	nShellStep	 			DD	0	; DLL可能会多次进入shell,通过统计进入步数来判断是EXE还是DLL
	PresentImageBase		DD	?
	;LuanchBase	 			DD	?	; 需要外壳程序写入	RVA
	;LuanchAllocatedBase	 	DD	?
	;nLuanchOriginalSize		DD	?
	;nLuanchPackSize			DD	?	; 需要外壳程序写入
	LuanchPNode				SHELL_PACK_INFO_NODE <>	; 需要外壳写入
	szVirtualAlloc	 		DB	'VirtualAlloc', 0
	VirtualAllocAddr 		DD	0
	TlsTable	 			DB	18h DUP (?)	; 暂时未使用到
INDUCTION_DATA ENDS

Proc_Unapck_Data PROTO STDCALL \
	, ShellVA:DWORD,
	PackNodeOffset:DWORD, \
	VirtualAllocAddr:DWORD

Proc_Unpack_Data_Xor PROTO STDCALL \
	, psrc:DWORD, \
	srclen:DWORD, \
	pdst:DWORD, \
	dstlen:DWORD

Proc_Unpack_Data_AP	PROTO STDCALL

; MInfo_ImpTabType
MIITT_NOTHING	EQU	0h	; 无任何操作
MIITT_MUTATED	EQU 1h	; 变异

; MInfo_RelocTabType
MIRTT_NOTHING	EQU 0h
MIRTT_MUTATED	EQU 1h

MUTATEDINFO_BITSEPERITEM EQU 1h

; ShellDataType
MImp		EQU 0h
MReloc		EQU 1h
MReserved	EQU 2h

SHELLDATANODE STRUCT
	_Type			DD ?	; ShellDataType
	OriginalAddr	DD ?	; RVA to IamgeBase
	MutatedAddr		DD ?	; RVA to ImageBase
SHELLDATANODE ENDS

LUANCH_DATA STRUCT
	OEP					DD	?	; 需要外壳程序写入
	OriginalImageBase	DD	?	; 需要外壳程序写入
	IsDll				DD	?	; 需要外壳程序写入
	MInfo				DD	?	; 需要外壳程序写入				
	Nodes				SHELLDATANODE  (8 * (TYPE DWORD) / MUTATEDINFO_BITSEPERITEM) DUP (<?, ?, ?>); 需要外壳程序写入	
	nLuanchAllocStep    DD	0
	szVirtualFree		DB	'VirtualFree', 0
	VirtualFreeADDR		DD	0
	szVirtualProct		DB	'VirtualProtect', 0
	ALIGN	TYPE DWORD
	VPAddr				DD	0
	szKer32DLLName		DB	'KERNEL32.dll', 0, 0
	; 已下数据需要从第一段SHELL复制到第二段SHELL
	; 三个函数次序不可改变
	GPAAddr				DD	0
	GMHAddr				DD	0
	LLAAddr				DD	0
	VirtualAllocAddr	DD	0
	aPDepackASMAddr		DD	0
	PresentImageBase	DD	0
LUANCH_DATA ENDS

comment /
	FirstThunk|DLLName[32]|nFunc|FuncName[32]...
/
SHELL_MUTATED_IMPTAB_DLLNODE_APINODE UNION
	Ordinal		DWORD	?
	ProcName	BYTE	128 DUP (?)
SHELL_MUTATED_IMPTAB_DLLNODE_APINODE ENDS

SHELL_MUTATED_IMPTAB_DLLNODE	STRUCT
	FirstThunk	DD	?
	DLLName		DB	32 DUP (?)
	nFunc		DD	?
	FuncName	SHELL_MUTATED_IMPTAB_DLLNODE_APINODE <?>
SHELL_MUTATED_IMPTAB_DLLNODE 	ENDS

SHELL_MUTATED_RELOCTAB STRUCT
	Type_			DB	?
	FirstTypeRVA	DD	?
	Offset_			DW	?
SHELL_MUTATED_RELOCTAB ENDS

comment /
	Description:
		C convention
		unsigned int aP_depack_safe(const void *source,
                            unsigned int srclen,
                            void *destination,
                            unsigned int dstlen);
/
Proc_aP_depack_asm_safe PROTO


comment /
	Description:	
	Parameters:	_RuntimeImageBase		DWORD
				_MutateImportRVA		DWORD	RVA to ImageBase
				_GPAAddr				DWORD
				_GMHAddr				DWORD
				_LLAAddr				DWORD
				dwVPAddr				DWORD
/
Proc_UnmutateImpTab	PROTO STDCALL \
	, _RuntimeImageBase:DWORD, \
	_MutateImportRVA:DWORD, \
	_GPAAddr:DWORD, \
	_GMHAddr:DWORD, \
	_LLAAddr:DWORD, \
	dwVPAddr:DWORD

comment /
	Description:	初始化原输入表
					C convention
	Parameters:		_RuntimeImageBase	DWORD
					_OriginalImportRVA	DWORD	RVA to ImageBase
					_GPAAddr			DWORD	
					_GMHAddr			DWORD
					_LLAAddr			DWORD
/
Proc_InitOrigianlImport PROTO STDCALL \
	, _RuntimeImageBase:DWORD, \
	_OriginalImportRVA:DWORD, \
	_GPAAddr:DWORD, \
	_GMHAddr:DWORD, \
	_LLAAddr:DWORD

comment	/
*description:	修正变异重定位信息
*params:		[in]_OrigianlImageBase:DWORD
*				[in]_RuntimeImageBase:DWORD
*				[in + out]_MutatedRelocTabRVA:DWORD
*				[in]dwVPAddr:DWORD
*reurns:		[eax] ERR_CODES
/
Proc_UnmutateRelocTab PROTO STDCALL\
	, _OrigianlImageBase:DWORD, \
	_RuntimeImageBase:DWORD, \
	_MutatedRelocTabRVA:DWORD, \
	dwVPAddr:DWORD

PROC_TEST_MINFO PROTO STDCALL , _MInfo:DWORD, _Type:DWORD	

PROC_Get_ProcAddress PROTO STDCALL \
	, pszDLLName:DWORD, pszAPIName:DWORD, dwGMHAddr:DWORD, dwLLAddr:DWORD, dwGPAAddr:DWORD

ENDIF  ; __ASMSHELL_INC__