#include <string>

class InlineHook
{

};
/*
class IatHook{

};
*/

/*
jmp xxxxx
原理有问题 jmp后应该保证自动jmp回来 待实现 在hook阶段unhook 对于多线程比较灾难 可以参考Frida的HOOK 此处仅HOOK WIN32 X64实现

至少目标达到 Linux X64/Linux Arm64 Arm64指令集和ELF格式我不太熟悉
void Hook()
{
	DWORD OldProtect;
	if (VirtualProtect(OldMessageBoxW, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
	{
		memcpy(Ori_Code, OldMessageBoxW, 12);               // 拷贝原始机器码指令
		*(PINT64)(HookCode + 2) = (INT64)&MyMessageBoxW;    // 填充90为指定跳转地址
	}
	memcpy(OldMessageBoxW, &HookCode, sizeof(HookCode));    // 拷贝Hook机器指令
}

void UnHook()
{
	memcpy(OldMessageBoxW, &Ori_Code, sizeof(Ori_Code));    // 恢复hook原始代码
}
*/