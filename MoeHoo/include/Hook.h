#include <string>
// 跨平台兼容个灯
#include <iostream>
#include <Windows.h>

bool Hook(UINT64 dwAddr, LPVOID lpFunction)
{
	void *targetFunction = reinterpret_cast<void *>(dwAddr);
	INT64 distance = reinterpret_cast<INT64>(lpFunction) - dwAddr - 5;
	//MessageBoxA(0,std::to_string(static_cast<INT64>(distance)).c_str(),"1",0);
	DWORD oldProtect;
	if (!VirtualProtect(targetFunction, 10, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		//MessageBoxA(0,std::to_string(static_cast<INT64>(distance)).c_str(),"2",0);
		std::cerr << "VirtualProtect failed." << std::endl;
		return false;
	}
	// 有一个符号位
	if (distance >= INT32_MIN && distance <= INT32_MAX)
	{
		// 直接进行小跳转
		BYTE call[] = {0xE8, 0x00, 0x00, 0x00, 0x00}; // call instruction
		*reinterpret_cast<INT32 *>(&call[1]) = static_cast<INT32>(distance);
		memcpy(targetFunction, call, sizeof(call));
	}
	else
	{
		// 距离过远
		// MessageBoxA(0,std::to_string(static_cast<INT64>(distance)).c_str(),"跳转距离",0);
		return false;
		
		//进行64Bit跳转
	}
	// 恢复原来的内存保护属性
	if (!VirtualProtect(targetFunction, 10, oldProtect, &oldProtect))
	{
		return false;
	}

	return true;
}
INT64 GetFunctionAddress(UINT64 ptr)
{
	// 读取操作码
	const char *hptr = reinterpret_cast<const char *>(ptr);
	unsigned char opcode = static_cast<unsigned char>(hptr[0]);
	if (opcode != 0xE8)
	{
		std::cerr << "Not a call instruction!" << std::endl;
		return 0;
	}

	// 读取相对偏移量
	int32_t relativeOffset = *reinterpret_cast<const int32_t *>(hptr + 1);

	// 计算函数地址
	INT64 callAddress = reinterpret_cast<INT64>(hptr) + 5; // call 指令占 5 个字节
	INT64 functionAddress = callAddress + relativeOffset;

	return functionAddress;
}
