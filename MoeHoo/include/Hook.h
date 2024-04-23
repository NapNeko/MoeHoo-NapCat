#include <string>
// 跨平台兼容个灯
#include <iostream>
#include <Windows.h>

// 实现搜索某指针上下2GB的可用内存 进行填充远跳JMP 填充完成返回填充内存首地址 失败返回nullptr
void *SearchAndFillJump(void *baseAddress, void *targetAddress)
{
	unsigned char jumpInstruction[14] = {
		0x49, 0xBB,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x41, 0xFF, 0xE3};

	memcpy(&jumpInstruction[2], &targetAddress, sizeof(targetAddress));

	MEMORY_BASIC_INFORMATION mbi;
	char *searchStart = static_cast<char *>(baseAddress) - 0x80000000;
	char *searchEnd = static_cast<char *>(baseAddress) + 0x80000000;

	while (searchStart < searchEnd)
	{
		if (VirtualQuery(searchStart, &mbi, sizeof(mbi)) == 0)
		{
			break;
		}
		if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE))
		{
			if (mbi.RegionSize >= sizeof(jumpInstruction))
			{
				memcpy(mbi.BaseAddress, jumpInstruction, sizeof(jumpInstruction));
				return mbi.BaseAddress;
			}
		}
		searchStart += mbi.RegionSize;
	}
	return nullptr;
}

bool Hook(UINT64 dwAddr, LPVOID lpFunction)
{
	void *targetFunction = reinterpret_cast<void *>(dwAddr);
	INT64 distance = reinterpret_cast<INT64>(lpFunction) - dwAddr - 5;
	// MessageBoxA(0,std::to_string(static_cast<INT64>(distance)).c_str(),"1",0);
	DWORD oldProtect;
	if (!VirtualProtect(targetFunction, 10, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		// MessageBoxA(0,std::to_string(static_cast<INT64>(distance)).c_str(),"2",0);
		std::cerr << "VirtualProtect failed." << std::endl;
		return false;
	}
	// 有一个符号位
	void *new_ret = nullptr;
	if (distance < INT32_MIN || distance > INT32_MAX)
	{
		new_ret = SearchAndFillJump(targetFunction, (void *)lpFunction);
		if (new_ret == nullptr)
		{
			MessageBoxA(0, "error", "跳转失败", 0);
			return false;
		}
		distance = reinterpret_cast<INT64>(new_ret) - dwAddr - 5;
	}
	// 直接进行小跳转
	BYTE call[] = {0xE8, 0x00, 0x00, 0x00, 0x00}; // 短CALL
	*reinterpret_cast<INT32 *>(&call[1]) = static_cast<INT32>(distance);
	memcpy(targetFunction, call, sizeof(call));
	// 恢复原来的内存保护属性
	if (!VirtualProtect(targetFunction, 10, oldProtect, &oldProtect))
	{
		return false;
	}

	return true;
}
