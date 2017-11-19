; x86

.586P
.MODEL FLAT,STDCALL
OPTION CASEMAP:NONE


INCLUDE c:\masm32\include\windows.inc
INCLUDE ASMshell.inc 


.CODE
Label_Shell_Start	LABEL	DWORD
Label_Induction_Start	LABEL	DWORD

_EntryPoint:
	pushad
	call __next0

Label_Faked_ImpTab_Start	LABEL	DWORD

Label_Induction_Import_Start 	LABEL	DWORD
	ImportTable		MY_IMAGE_IMPORT_DESCRIPTOR <<GPAAddr - Label_Shell_Start>, 0, 0, (DLLName - Label_Shell_Start), (GPAAddr - Label_Shell_Start)>
	DumbDescriptor	MY_IMAGE_IMPORT_DESCRIPTOR <<0>, 0, 0, 0, 0>       
Label_Induction_Import_End	LABEL	DWORD	
	
Label_Induction_IAT_Start	LABEL	DWORD
	; 三个函数次序不可改变
	GPAAddr	MY_IMAGE_IMPORT_THUNK	<<GPAThunk - Label_Shell_Start>>	; GetProcAddress Address
	GMHAddr	MY_IMAGE_IMPORT_THUNK	<<GMHThunk - Label_Shell_Start>>	; GetModuleHandle Address
	LLAAddr	MY_IMAGE_IMPORT_THUNK	<<LLAThunk - Label_Shell_Start>>	; LoadLibraryA Address
			MY_IMAGE_IMPORT_THUNK	<<0>>
Label_Induction_IAT_End		LABEL	DWORD

	; DLLName
	DLLName	DB	'KERNEL32.dll', 0, 0
	
	; Thunks
	GPAThunk	MY_IMAGE_IMPORT_BY_NAME	<0, 'GetProcAddress'>
	GMHThunk	MY_IMAGE_IMPORT_BY_NAME	<0, 'GetModuleHandleA'>
	LLAThunk	MY_IMAGE_IMPORT_BY_NAME	<0, 'LoadLibraryA'>

Label_Faked_ImpTab_End	LABEL	DWORD

Label_Induction_Data_Start	LABEL	DWORD
	InductionData INDUCTION_DATA <>
Label_Induction_Data_End	LABEL	DWORD

__next0:	
	; 获取程序入口点 ebp = 入口点地址, 为后面提供寻址作用
	pop 	ebp
	sub		ebp, (Label_Induction_Import_Start - Label_Induction_Start)
	
	; *  以下代码是处理DLL时起作用  *
	; 当DLL再次进入时，第二段shell已经解密，因此可以直接进入
	mov		eax, dword ptr [ebp + (InductionData.nShellStep - Label_Induction_Start)]
	.if	eax != 0
		push	ebp
		jmp		dword ptr [ebp + (InductionData.LuanchPNode.AllocatedAddr - Label_Induction_Start)]
	.endif
	inc		dword ptr [ebp + (InductionData.nShellStep - Label_Induction_Start)]	
	
	;  如果是DLL，取当前映像基址；如果是EXE在后面会用Getmulehandle取基址的
	mov		eax, dword ptr [esp + 24h]
	mov		dword ptr [ebp + (InductionData.PresentImageBase - Label_Induction_Start)], eax
	
	; *  准备解压缩第二段外壳代码  *
	; GetModuleHandle(DLLName)
	lea		esi, [ebp + (DLLName - Label_Induction_Start)]
	push	esi
	call	dword ptr [ebp + (GMHAddr - Label_Induction_Start)]
	
	; GetProcAddress(handle(DLLName),"VirtualAlloc")
	lea		esi, [ebp + (InductionData.szVirtualAlloc - Label_Induction_Start)]
	push	esi
	push	eax
	call	dword ptr [ebp + (GPAAddr - Label_Induction_Start)]
	mov		dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)],eax
	
	; VirtualAlloc(0, nLuanchOriginalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	;push	PAGE_EXECUTE_READWRITE
	;push	MEM_COMMIT
	;push	dword ptr [ebp + (InductionData.nLuanchOriginalSize - Label_Induction_Start)]
	;push	0
	;call	dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]
	
	; 将外壳第二段地址放到LuanchAllocatedBase，DLL退出时会用到
	;mov		dword ptr [ebp + (InductionData.LuanchAllocatedBase - Label_Induction_Start)], eax
	
	; *  解压缩第二段外壳代码  *
	;push 	dword ptr [ebp + (InductionData.nLuanchOriginalSize - Label_Induction_Start)] 
	;push	dword ptr [ebp + (InductionData.LuanchAllocatedBase - Label_Induction_Start)]
	;push 	dword ptr [ebp + (InductionData.nLuanchPackSize - Label_Induction_Start)]
	;mov		ebx, dword ptr [ebp + (InductionData.LuanchBase - Label_Induction_Start)]
	;add		ebx, ebp
	;push	ebx
	;call	Proc_aP_depack_asm_safe
	;add		esp, 4 * TYPE DWORD
	;pop		edx	; 对应上面的push eax
	
	push	[ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]
	lea		eax, [ebp + (InductionData.LuanchPNode - Label_Induction_Start)]
	sub		eax, ebp
	push	eax
	push	ebp
	call	Proc_Unpack_Data

	mov		edx, [ebp + (InductionData.LuanchPNode.AllocatedAddr - Label_Induction_Start)]
	; 复制三个初始函数的地址到第二段外壳的数据表中
	mov		ecx, 3h
	lea		esi, [ebp + (GPAAddr - Label_Induction_Start)]
	lea		edi, [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
MoveThreeFuncAddr:
	mov		eax, dword ptr [esi]
	mov		dword ptr [edi], eax
	add		esi, TYPE DWORD
	add		edi, TYPE DWORD
	loop	MoveThreeFuncAddr
	
	; 复制ap_depack_asm地址到第二段外壳的数据表中
	lea		eax, Proc_aP_depack_asm_safe
	mov		dword ptr [edx + (LuanchData.aPDepackASMAddr - Label_Luanch_Start)], eax
	
	; 复制VirtualAlloc地址到第二段外壳的数据表中
	mov		eax, dword ptr [ebp + (InductionData.VirtualAllocAddr - Label_Induction_Start)]	
	mov		dword ptr [edx + (LuanchData.VirtualAllocAddr - Label_Luanch_Start)], eax
	
	; 复制PresentImageBase到第二段外壳的数据表中
	mov 	eax, dword ptr [ebp + (InductionData.PresentImageBase - Label_Induction_Start)]
	mov 	dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)], eax
	
	; 跳转到第二段SHELL代码中
	push	ebp
	jmp		edx

Proc_Unpack_Data PROC STDCALL PRIVATE \
	USES ebx ecx edx esi edi \
	, ShellVA:DWORD,
	PackNodeOffset:DWORD, \
	VirtualAllocAddr:DWORD

	.IF (ShellVA == 0) || (PackNodeOffset == 0) || (VirtualAllocAddr == 0)
		mov		eax, ERR_INVALIDPARAMS
		ret
	.ENDIF 

	push	PAGE_EXECUTE_READWRITE
	push	MEM_COMMIT
	mov		esi, ShellVA
	add		esi, PackNodeOffset		
	push	(SHELL_PACK_INFO_NODE PTR [esi]).OriginalSize
	push	0
	call	VirtualAllocAddr

	mov		esi, ShellVA
	add		esi, PackNodeOffset		
	.IF		eax != 0
		mov		(SHELL_PACK_INFO_NODE PTR [esi]).AllocatedAddr, eax
	.ELSE
		xor		eax, eax
		mov		(SHELL_PACK_INFO_NODE PTR [esi]).AllocatedAddr, eax
		mov		eax, ERR_FAILED
		ret
	.ENDIF

	mov		eax, (SHELL_PACK_INFO_NODE PTR [esi]).Type_
	.IF eax == PT_Xor
		push	(SHELL_PACK_INFO_NODE PTR [esi]).OriginalSize
		push	(SHELL_PACK_INFO_NODE PTR [esi]).AllocatedAddr
		push	(SHELL_PACK_INFO_NODE PTR [esi]).PackedSize
		mov		eax, (SHELL_PACK_INFO_NODE PTR [esi]).PackedOffset
		add		eax, ShellVA
		push	eax
		call	Proc_Unpack_Data_Xor
	.ELSEIF eax == PT_AP	
		call	Proc_Unpack_Data_AP
	.ELSE
		mov		eax, ERR_INVALIDPARAMS
	.ENDIF
	
	ret
Proc_Unpack_Data ENDP

Proc_Unpack_Data_Xor PROC STDCALL PRIVATE \
	USES ebx esi edi \
	, psrc:DWORD, \
	srclen:DWORD, \
	pdst:DWORD, \
	dstlen:DWORD

	.IF (psrc == 0) || (srclen == 0) || (pdst == 0) || (dstlen == 0)
		mov		eax, ERR_INVALIDPARAMS
		ret
	.ENDIF 

	mov		eax, psrc
	mov		ah, byte ptr [eax]
	mov		ebx, 1 * TYPE BYTE
	mov		esi, psrc
	mov		edi, pdst

	.WHILE ebx < srclen
		mov		al, byte ptr [esi + ebx]
		xor		al, ah
		mov		byte ptr [edi + ebx - 1], al
		inc		ebx
	.ENDW

	mov		eax, ERR_SUCCEEDED
	ret
Proc_Unpack_Data_Xor ENDP

Proc_Unpack_Data_AP	PROC STDCALL PRIVATE
	mov		eax, ERR_SUCCEEDED
	ret
Proc_Unpack_Data_AP ENDP

Label__aP_depack_asm_safe_Start LABEL DWORD

getbitM MACRO
LOCAL stillbitsleft

    add    dl, dl
    jnz    stillbitsleft

    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    dl, [esi]
    inc    esi
    add    dl, dl
    inc    dl
stillbitsleft:
ENDM getbitM

domatchM MACRO reg
    push   ecx
    mov    ecx, [esp + 60]    ; ecx = dstlen
    sub    ecx, [esp + 4]     ; ecx = num written
    cmp    reg, ecx
    pop    ecx
    ja     return_error

    sub    [esp], ecx         ; write ecx bytes to destination
    jc     return_error       ;

    push   esi
    mov    esi, edi
    sub    esi, reg
    rep    movsb
    pop    esi
ENDM domatchM

getgammaM MACRO reg
LOCAL getmorebits
    mov    reg, 1
getmorebits:
    getbitM
    adc    reg, reg
    jc     return_error
    getbitM
    jc     getmorebits
ENDM getgammaM

comment /
	Description:
		C convention
		unsigned int aP_depack_safe(const void *source,
                            unsigned int srclen,
                            void *destination,
                            unsigned int dstlen);
/
Proc_aP_depack_asm_safe PROC

    pushad

    mov    esi, [esp + 36]    ; C calling convention
    mov    eax, [esp + 40]
    mov    edi, [esp + 44]
    mov    ecx, [esp + 48]

    push   eax
    push   ecx

    test   esi, esi
    jz     return_error

    test   edi, edi
    jz     return_error

    cld
    xor    edx, edx

literal:
    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    add    esi, 1

    sub    dword ptr [esp], 1 ; write one byte to destination
    jc     return_error       ;

    mov    [edi], al
    add    edi, 1

    mov    ebx, 2

nexttag:
    getbitM
    jnc    literal

    getbitM
    jnc    codepair

    xor    eax, eax
    getbitM
    jnc    shortmatch

    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    getbitM
    adc    eax, eax
    jz     thewrite

    mov    ebx, [esp + 56]    ; ebx = dstlen
    sub    ebx, [esp]         ; ebx = num written
    cmp    eax, ebx
    ja     return_error

    push   edi
    sub    edi, eax
    mov    al, [edi]
    pop    edi

thewrite:
    sub    dword ptr [esp], 1 ; write one byte to destination
    jc     return_error       ;

    mov    [edi], al
    inc    edi

    mov    ebx, 2

    jmp    nexttag

codepair:
    getgammaM eax

    sub    eax, ebx

    mov    ebx, 1

    jnz    normalcodepair

    getgammaM ecx

    domatchM ebp

    jmp    nexttag

normalcodepair:
    dec    eax

    test   eax, 0ff000000h
    jnz    return_error

    shl    eax, 8

    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    inc    esi

    mov    ebp, eax

    getgammaM ecx

    cmp    eax, 32000
    sbb    ecx, -1

    cmp    eax, 1280
    sbb    ecx, -1

    cmp    eax, 128
    adc    ecx, 0

    cmp    eax, 128
    adc    ecx, 0

    domatchM eax

    jmp    nexttag

shortmatch:
    sub    dword ptr [esp + 4], 1 ; read one byte from source
    jc     return_error           ;

    mov    al, [esi]
    inc    esi

    xor    ecx, ecx
    db     0c0h, 0e8h, 001h
    jz     donedepacker

    adc    ecx, 2

    mov    ebp, eax

    domatchM eax

    mov    ebx, 1

    jmp    nexttag

return_error:
    add    esp, 8

    popad

    or     eax, -1            ; return APLIB_ERROR in eax

    ret

donedepacker:
    add    esp, 8

    sub    edi, [esp + 40]
    mov    [esp + 28], edi    ; return unpacked length in eax

    popad

    ret
	
Proc_aP_depack_asm_safe ENDP
Label__aP_depack_asm_safe_End LABEL DWORD
	
Label_Induction_End LABEL DWORD


Label_Luanch_Start	LABEL	DWORD
	; edx = Allocated Label_Luanch_Start VA
	call	$+5
	pop		edx
	sub		edx, 5h

	; ebp = Label_Induction_Start VA
	pop		ebp

	; 如果是DLL，则跳到OEP
	mov		eax, dword ptr [ebp + (InductionData.nShellStep - Label_Shell_Start)]
	mov		ebx, dword ptr [edx + (LuanchData.IsDll - Label_Luanch_Start)]
	.if		(eax > 1) && (ebx != 0)
			;dll退出时从这里进入OEP	
			; TODO 修改跳转位置，支持再次反调试
	        jmp _Return_OEP
	.endif
	
	; 如果是EXE文件，则用GetModuleHandle(NULL)获取映射中当前模块基址
	mov		eax, dword ptr [edx + (LuanchData.IsDll - Label_Luanch_Start)]
	.if		eax == 0
			push	0
			call	dword ptr [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
			mov		dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)], eax
	.endif

	; 获取VirtualFree函数地址
	push	dword ptr [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
	push	dword ptr [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
	push	dword ptr [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
	lea		eax, dword ptr [edx + (LuanchData.szVirtualFree - Label_Luanch_Start)]
	push	eax
	lea		eax, dword ptr [edx + (LuanchData.szKer32DLLName - Label_Luanch_Start)]
	push	eax
	call	PROC_Get_ProcAddress
	mov		dword ptr [edx + (LuanchData.VirtualFreeADDR - Label_Luanch_Start)], eax
	
	; 获取VirtualProtect函数地址
	push	dword ptr [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
	push	dword ptr [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
	push	dword ptr [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
	lea		eax, dword ptr [edx + (LuanchData.szVirtualProct - Label_Luanch_Start)]
	push	eax
	lea		eax, dword ptr [edx + (LuanchData.szKer32DLLName - Label_Luanch_Start)]
	push	eax
	call	PROC_Get_ProcAddress
	mov		dword ptr [edx + (LuanchData.VPAddr - Label_Luanch_Start)], eax

	; *  TODO: 解压缩各区块  *

	; *  恢复原输入表  *
	push	MImp
	push	DWORD PTR [edx + (LuanchData.MInfo - Label_Luanch_Start)]
	call	PROC_TEST_MINFO
	.IF		eax == 0
		push	DWORD PTR [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
		lea		eax, DWORD PTR [edx + (LuanchData.Nodes.OriginalAddr - Label_Luanch_Start)]
		add		eax, MImp * TYPE LuanchData.Nodes
		push	DWORD PTR [eax]
		push	DWORD PTR [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)]
		call	Proc_InitOrigianlImport
	.ELSE
		push	DWORD PTR [edx + (LuanchData.VPAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.LLAAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.GMHAddr - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.GPAAddr - Label_Luanch_Start)]
		lea		eax, DWORD PTR [edx + (LuanchData.Nodes.MutatedAddr - Label_Luanch_Start)]
		add		eax, MImp * TYPE LuanchData.Nodes
		push	DWORD PTR [eax]
		push	DWORD PTR [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)]
		call	Proc_UnmutateImpTab
	.ENDIF
	
	; *  修正重定位数据  *
	push	MReloc
	push	DWORD PTR [edx + (LuanchData.MInfo - Label_Luanch_Start)]
	call	PROC_TEST_MINFO
	.IF		eax == 0
		xor		eax, eax
	.ELSE
		push	DWORD PTR [edx + (LuanchData.VPAddr - Label_Luanch_Start)]
		lea		eax, DWORD PTR [edx + (LuanchData.Nodes.MutatedAddr - Label_Luanch_Start)]
		add		eax, MReloc * TYPE LuanchData.Nodes
		push	DWORD PTR [eax]
		push	DWORD PTR [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)]
		push	DWORD PTR [edx + (LuanchData.OriginalImageBase - Label_Luanch_Start)]
		call	Proc_UnmutateRelocTab
	.ENDIF
	
	; *  anti  dump  *
	
	
	; *  开始跳转到OEP  *
	; TODO: DLL情况未知
	inc 	dword ptr [ebp + (InductionData.nShellStep - Label_Induction_Start)]
	mov		eax, dword ptr [edx + (LuanchData.OEP - Label_Luanch_Start)]
	add		eax, dword ptr [edx + (LuanchData.PresentImageBase - Label_Luanch_Start)]
	mov		dword ptr [edx + (LABEL_OEP - Label_Luanch_Start)], eax
_Return_OEP: 
	popad
	DB		68h	; opcode of push
LABEL_OEP LABEL BYTE 
	DD		0
	ret

Lable_Luanch_Data_Start	LABEL	DWORD
LuanchData	LUANCH_DATA	<>
Lable_Luanch_Data_End	LABEL 	DWORD

MACRO_VP_CHANGE MACRO
	; 更改对应内存块访问权限
	mov		OldProt, 0
	; 保存地址
	lea		eax, DWORD PTR [edi + edx]
	mov		ProtAddr, eax	

	push	ebx
	push	ecx
	push	edx
	push	edi
	push	esi

	lea		eax, OldProt
	push	eax	
	push	PAGE_EXECUTE_READWRITE
	push	4	
	push	ProtAddr
	call	dwVPAddr

	pop		esi
	pop		edi
	pop		edx
	pop		ecx
	pop		ebx
ENDM

MACRO_VP_RESTORE MACRO
	; 还原内存页访问权限
	.IF  OldProt != 0
		push	ebx
		push	ecx
		push	edx
		push	edi
		push	esi

		lea		ebx, OldProt
		push	ebx
		push	OldProt
		push	4
		push	ProtAddr
		call	dwVPAddr

		pop		esi
		pop		edi
		pop		edx
		pop		ecx
		pop		ebx
	.ENDIF
ENDM


ORDINAL_FLAG_DWORD	EQU	80000000h	
comment /
	Description:	
	Parameters:	_RuntimeImageBase		DWORD
				_MutateImportRVA		DWORD	RVA to ImageBase
				_GPAAddr				DWORD
				_GMHAddr				DWORD
				_LLAAddr				DWORD
				dwVPAddr				DWORD
/
Proc_UnmutateImpTab	PROC STDCALL PRIVATE \
	USES ebx ecx edx esi edi \
	, _RuntimeImageBase:DWORD, \
	_MutateImportRVA:DWORD, \
	_GPAAddr:DWORD, \
	_GMHAddr:DWORD, \
	_LLAAddr:DWORD, \
	dwVPAddr:DWORD
	
	LOCAL	ProtAddr:DWORD
	LOCAL	OldProt:DWORD

	mov		edx, _RuntimeImageBase
	mov		esi, _MutateImportRVA
	mov		edi, (SHELL_MUTATED_IMPTAB_DLLNODE PTR [edx + esi]).FirstThunk
	
	.WHILE		edi != 0
		
		; eax = GetModuleHandleA(MutateImport.DLLName)
		; if (eax == 0)	LoadLibraryA(MutateImport.DLLName)
		push 	edx
		lea 	eax, (SHELL_MUTATED_IMPTAB_DLLNODE PTR [edx + esi]).DLLName
		push 	eax
		call 	_GMHAddr	
		pop 	edx
		.IF 	eax == 0
			push 	edx
			lea 	eax, (SHELL_MUTATED_IMPTAB_DLLNODE PTR [edx + esi]).DLLName
			push 	eax
			call 	_LLAAddr	
			pop 	edx
		.ENDIF
		
		; 获取所有函数的地址
		; ebx = hDLL
		; ecx = SHELL_MUTATED_IMPTAB_DLLNODE.nFunc
		; esi = SHELL_MUTATED_IMPTAB_DLLNODE.SHELL_MUTATED_IMPTAB_DLLNODE_APINODE
		; while(ecx != 0)
		; {
		; 		if (esi is ordinal)
		;		{
		;			eax = ordinal and 0000ffffh
		;		}
		;		else
		;		{
		;			eax = szFuncName
		;		}
		;		GetProcAddress(hDLL, eax)
		;		OriginalImport.IAT[n] = eax 
		;
		;		esi += 32;	移动到下一个THUNK
		;		ecx--
		; }
		mov 	ebx, eax
		mov		ecx, (SHELL_MUTATED_IMPTAB_DLLNODE PTR [edx + esi]).nFunc
		add		esi, TYPE SHELL_MUTATED_IMPTAB_DLLNODE.FirstThunk
		add		esi, SIZEOF SHELL_MUTATED_IMPTAB_DLLNODE.DLLName
		add		esi, TYPE SHELL_MUTATED_IMPTAB_DLLNODE.nFunc
		.WHILE  ecx != 0
			mov 	eax, DWORD PTR [edx + esi]
			and 	eax, ORDINAL_FLAG_DWORD
			.IF 	eax != 0
				; ORDINAL
				mov		eax, DWORD PTR [edx + esi]
				and 	eax, 0000ffffh
			.ELSE
				; STRING 
				lea 	eax, DWORD PTR [edx + esi]
			.ENDIF 

			push 	ecx
			push 	edx
			push 	ebx			
			push 	eax
			push 	ebx
			call 	_GPAAddr
			pop 	ebx
			pop 	edx
			pop 	ecx

			push	eax
			MACRO_VP_CHANGE
			pop		eax
			mov		DWORD PTR [edx + edi], eax
			MACRO_VP_RESTORE
			
			add 	esi, TYPE SHELL_MUTATED_IMPTAB_DLLNODE_APINODE 
			add 	edi, TYPE DWORD
			dec 	ecx
		.ENDW
		
		mov		edi, (SHELL_MUTATED_IMPTAB_DLLNODE PTR [edx + esi]).FirstThunk
	.ENDW	
	
	ret 
	
Proc_UnmutateImpTab ENDP


comment /
	Description:	初始化原输入表
	Parameters:		_RuntimeImageBase	DWORD
					_OriginalImportRVA	DWORD	RVA to ImageBase
					_GPAAddr			DWORD	
					_GMHAddr			DWORD
					_LLAAddr			DWORD
/
Proc_InitOrigianlImport PROC STDCALL PRIVATE \
	USES ebx ecx edx esi edi \
	, _RuntimeImageBase:DWORD, _OriginalImportRVA:DWORD, _GPAAddr:DWORD, _GMHAddr:DWORD, _LLAAddr:DWORD
	
	mov 	edx, _RuntimeImageBase
	mov 	esi, _OriginalImportRVA
	
	mov 	eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).FirstThunk
	.WHILE  eax != 0
		mov 	edi, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).FirstThunk
		
		; eax = GetModuleHandleA(Import.DLLName)
		; if (eax == 0)	LoadLibraryA(Import.DLLName)
		; ebx = hDLL
		push	edx 
		mov 	eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).DLLName
		add 	eax, edx
		push 	eax
		call    DWORD PTR [_GMHAddr]
		pop		edx
		.IF eax == 0
			push 	edx
			mov 	eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).DLLName
			add 	eax, edx 
			push 	eax
			call 	DWORD PTR [_LLAAddr]
			pop		edx
		.ENDIF
		mov		ebx, eax 
		
		mov 	eax, DWORD PTR [edx + edi]
		.WHILE	eax != 0
			push 	ebx
			push	edx
			mov 	ecx, DWORD PTR [edx + edi]
			push 	ecx
			and		ecx, ORDINAL_FLAG_DWORD
			.IF		ecx == 0
			;	STRING
				pop 	ecx
				; GetProcAddress(eax, Import.FirstThunk[n])
				lea		ecx, DWORD PTR [edx + ecx + TYPE WORD]	;越过Hint
			.ELSE
			;	ORDINAL
				pop		ecx
				and		ecx, 0000ffffh
			.ENDIF
			push 	ecx
			push	ebx 
			call	DWORD PTR [_GPAAddr]
			pop		edx
			pop 	ebx
			
			; Import.FirstThunk[n] = eax
			mov		DWORD PTR [edx + edi], eax
			
			; 调整指针指向下一个IMPORT_THUNK_DATA
			add 	edi, TYPE DWORD
			mov		eax, DWORD PTR [edx + edi]
		.ENDW
		add 	esi, TYPE MY_IMAGE_IMPORT_DESCRIPTOR; 调整指针指向下一个IMPORT_DESCRIPTOR
		mov		eax, (MY_IMAGE_IMPORT_DESCRIPTOR PTR [edx + esi]).FirstThunk
	.ENDW
	
	ret
	
Proc_InitOrigianlImport ENDP

PROC_TEST_MINFO PROC STDCALL PRIVATE	\
	USES	ebx	ecx	\
	, _MInfo:DWORD, _Type:DWORD	

	mov		eax, _MInfo
	mov		ebx, 0
	add		ebx, 1
	mov		ecx, _Type
	shl		ebx, cl 
	and		eax, ebx

	ret
PROC_TEST_MINFO ENDP 


comment	/
*description:	修正变异重定位信息
*params:		[in]_OriginalImageBase:DWORD
*				[in]_RuntimeImageBase:DWORD
*				[in + out]_MutatedRelocTabRVA:DWORD
*				[in]dwVPAddr:DWORD
*reurns:		[eax] ERR_CODES
/
Proc_UnmutateRelocTab PROC STDCALL PRIVATE \
	USES ebx ecx edx edi esi \
	, _OriginalImageBase:DWORD, \
	_RuntimeImageBase:DWORD, \
	_MutatedRelocTabRVA:DWORD, \
	dwVPAddr:DWORD

	LOCAL	Distance:DWORD
	LOCAL	OldProt:DWORD
	LOCAL	ProtAddr:DWORD

	.IF ([_OriginalImageBase] == 0) \
		|| ([_RuntimeImageBase] == 0) \
		|| ([_MutatedRelocTabRVA] == 0)
		mov		eax, ERR_INVALIDPARAMS
		ret
	.ENDIF 
	
	mov		edx, _RuntimeImageBase
	mov		esi, _MutatedRelocTabRVA

	mov		eax, _RuntimeImageBase 	
	sub		eax, _OriginalImageBase
	mov		Distance, eax
	
	mov		al, (SHELL_MUTATED_RELOCTAB PTR [edx + esi]).Type_ 
	.WHILE	al == IMAGE_REL_BASED_HIGHLOW 
		mov		edi, (SHELL_MUTATED_RELOCTAB PTR [edx + esi]).FirstTypeRVA
		.BREAK .IF (edi == 0)
		
		; 重定位块中第一个地址
		MACRO_VP_CHANGE
		mov		eax, Distance
		add		DWORD PTR [edx + edi], eax
		MACRO_VP_RESTORE

		; 重定位块中后续地址
		lea		esi, (SHELL_MUTATED_RELOCTAB PTR [edx + esi]).Offset_
		sub		esi, edx 
		.WHILE	WORD PTR [edx + esi] != 0
			xor		eax, eax
			mov		ax, WORD PTR [edx + esi]
			add		edi, eax
			MACRO_VP_CHANGE
			mov		eax, Distance
			add		DWORD PTR [edx + edi], eax
			MACRO_VP_RESTORE
			add		esi, TYPE SHELL_MUTATED_RELOCTAB.Offset_
		.ENDW
	
		add		esi, TYPE SHELL_MUTATED_RELOCTAB.Offset_
		mov		al, (SHELL_MUTATED_RELOCTAB PTR [edx + esi]).Type_ 
	.ENDW

	mov		eax, ERR_SUCCEEDED
	ret
Proc_UnmutateRelocTab ENDP


PROC_Get_ProcAddress PROC STDCALL PRIVATE \
	USES ecx edx \
	, pszDLLName:DWORD, pszAPIName:DWORD, dwGMHAddr:DWORD, dwLLAddr:DWORD, dwGPAAddr:DWORD

	; GetModuleHandle,Loadlibrary,GetProcAddress都会修改edx

	.IF (pszDLLName == 0) \
		|| (pszAPIName == 0) \
		|| (dwGMHAddr == 0) \
		|| (dwLLAddr == 0) \
		|| (dwGPAAddr == 0)
		mov		eax, 0
		ret
	.ENDIF

	push	pszDLLName
	call	dwGMHAddr
	
	; 如果DLL还未加载，则加载 
	.IF	eax == 0
		push	pszDLLName
		call	dwLLAddr
		.IF eax == 0
			ret
		.ENDIF
	.ENDIF

	push	pszAPIName
	push	eax
	call	dwGPAAddr

	ret
PROC_Get_ProcAddress ENDP

Label_Luanch_End	LABEL 	DWORD
Label_Shell_End	LABEL	DWORD

END