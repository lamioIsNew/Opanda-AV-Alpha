; pevm_jmp_test.asm -- JMP [IAT] thunk for PE_VM test (x86-32)
.386
.model flat, stdcall
option casemap:none

; MASM 默认给符号加一个下划线；写 _imp__Sleep@4 才能得到 __imp__Sleep@4
extern _imp__Sleep@4:DWORD

.code
thunk_sleep PROC ms:DWORD
    jmp dword ptr [_imp__Sleep@4]
thunk_sleep ENDP

END
