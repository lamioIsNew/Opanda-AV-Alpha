/* pevm_jmp_test.c -- 仅用于 PE_VM 的良性 JMP [IAT] 测试（x86-32）
 *
 * 真正的 thunk 在 pevm_jmp_test.asm 中：
 *     jmp dword ptr [__imp__Sleep@4]
 * 用于观察 api_dispatch() 对 CALL/JMP 的栈处理差异。
 */
#include <windows.h>

void __stdcall thunk_sleep(DWORD ms);

int main(void) {
    thunk_sleep(1);
    return 0;
}
