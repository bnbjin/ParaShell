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


INDUCTION_DATA STRUCT
	
	nShellStep	 		DD	0	; DLL可能会多次进入shell,通过统计进入步数来判断是EXE还是DLL
	
	LuanchBase	 		DD	?	; 需要外壳程序写入	RVA
	
	LuanchAllocBase	 	DD	?
	
	PresentImageBase	DD	?
	
	nLuanchOriginalSize	DD	?
	
	nLuanchPackSize		DD	?	; 需要外壳程序写入
	
	szVirtualAlloc	 	DB	'VirtualAlloc', 0
	
	VirtualAllocAddr 	DD	0
	
	TlsTable	 		DB	18h DUP (?)	; 暂时未使用到

INDUCTION_DATA ENDS


LUANCH_DATA STRUCT
OEP					DD	?	; 需要外壳程序写入
IsMutateImpTable	DD	?	; 需要外壳程序写入
MutateImpTableAddr	DD	?	; 需要外壳程序写入
OriginalImpTableAddr	DD	?	; 需要外壳程序写入
IsDll				DD	?	; 需要外壳程序写入
OriginalRelocAddr	DD	?	; 需要外壳程序写入	
SectionPackInfo		DB	0a0h DUP (?)	; 需要外壳程序写入
nLuanchAllocStep    DD	0
szVirtualFree		DB	'VirtualFree', 0
VirtualFreeADDR		DD	0
szKer32DLLName		DB	'KERNEL32.dll', 0, 0
hFile				DD	0
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
MUTATE_IMPORT_THUNK UNION
	Ordinal		DWORD	?
	ProcName	BYTE	32 DUP (?)
MUTATE_IMPORT_THUNK ENDS

MUTATE_IMPORT	STRUCT
	FirstThunk	DD	?
	DLLName		DB	32 DUP (?)
	nFunc		DD	?
	FuncName	MUTATE_IMPORT_THUNK <?>
MUTATE_IMPORT 	ENDS


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
/
Proc_UnmutateImport	PROTO C , _RuntimeImageBase:DWORD, _MutateImportRVA:DWORD, _GPAAddr:DWORD, _GMHAddr:DWORD, _LLAAddr:DWORD


comment /
	Description:	初始化原输入表
					C convention
	Parameters:		_RuntimeImageBase	DWORD
					_OriginalImportRVA	DWORD	RVA to ImageBase
					_GPAAddr			DWORD	
					_GMHAddr			DWORD
					_LLAAddr			DWORD
/
Proc_InitOrigianlImport PROTO C , _RuntimeImageBase:DWORD, _OriginalImportRVA:DWORD, _GPAAddr:DWORD, _GMHAddr:DWORD, _LLAAddr:DWORD


ENDIF  ; __ASMSHELL_INC__