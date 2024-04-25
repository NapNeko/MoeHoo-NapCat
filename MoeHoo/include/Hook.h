#include <string>
// 跨平台兼容个灯
#include <iostream>
// #define _LINUX_PLATFORM_
#if defined(_WIN_PLATFORM_)
#include <Windows.h>
#elif defined(_LINUX_PLATFORM_)
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#endif
int64_t GetFunctionAddress(int64_t ptr)
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
	int64_t callAddress = reinterpret_cast<int64_t>(hptr) + 5; // call 指令占 5 个字节
	int64_t functionAddress = callAddress + relativeOffset;

	return functionAddress;
}
// 实现搜索某指针上下2GB的可用内存 进行填充远跳JMP 填充完成返回填充内存首地址 失败返回nullptr
#if defined(_WIN_PLATFORM_)
void *SearchAndFillJump(void *baseAddress, void *targetAddress)
{
	unsigned char jumpInstruction[14] = {
		0x49, 0xBB,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x41, 0xFF, 0xE3};
	//*reinterpret_cast<int64_t *>(&jumpInstruction[2]) = reinterpret_cast<int64_t>(targetAddress);
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
		if (mbi.State == MEM_COMMIT)
		{
			for (char *addr = static_cast<char *>(mbi.BaseAddress); addr < static_cast<char *>(mbi.BaseAddress) + mbi.RegionSize - 1024 * 5; ++addr)
			{

				bool isFree = true;
				for (int i = 0; i < 1024 * 5; ++i)
				{
					if (addr[i] != 0)
					{
						isFree = false;
						break;
					}
				}
				if (isFree)
				{
					DWORD oldProtect;
					addr = addr + 0x200;
					// std::cout << std::to_string((int64_t)addr) << std::endl;
					VirtualProtect(addr, sizeof(jumpInstruction), PAGE_EXECUTE_READWRITE, &oldProtect);
					memcpy(addr, jumpInstruction, sizeof(jumpInstruction));
					if (!VirtualProtect(addr, sizeof(jumpInstruction), PAGE_EXECUTE_READ, &oldProtect))
					{
						return nullptr;
					}

					return addr;
				}
			}
		}
		searchStart += mbi.RegionSize;
	}
	return nullptr;
}
#elif defined(_LINUX_PLATFORM_)
// void *SearchAndFillJump(void *baseAddress, void *targetAddress)
// {
// 	unsigned char jumpInstruction[14] = {
// 		0x49, 0xBB,
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x41, 0xFF, 0xE3};

// 	memcpy(&jumpInstruction[2], &targetAddress, sizeof(targetAddress));

// 	// Iterate through memory regions
// 	char *searchStart = static_cast<char *>(baseAddress) - 0x80000000;
// 	char *searchEnd = static_cast<char *>(baseAddress) + 0x80000000;

// 	while (searchStart < searchEnd)
// 	{
// 		// Use mmap to query memory information
// 		struct stat mbi;
// 		if (mmap(searchStart, sizeof(mbi), PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
// 		{
// 			break;
// 		}

// 		// Check if the region is writable
// 		if (mbi.st_mode & S_IWUSR)
// 		{
// 			if (mbi.st_size >= sizeof(jumpInstruction))
// 			{
// 				memcpy(searchStart, jumpInstruction, sizeof(jumpInstruction));
// 				return searchStart;
// 			}
// 		}
// 		searchStart += mbi.st_size;
// 	}
// 	return nullptr;
// }
#endif

#if defined(_WIN_PLATFORM_)
bool Hook(uint64_t dwAddr, void * lpFunction)
{
	void *targetFunction = reinterpret_cast<void *>(dwAddr);
	int64_t distance = reinterpret_cast<int64_t>(lpFunction) - dwAddr - 5;
	// MessageBoxA(0,std::to_string(static_cast<int64_t>(distance)).c_str(),"1",0);
	DWORD oldProtect;
	if (!VirtualProtect(targetFunction, 10, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		// MessageBoxA(0,std::to_string(static_cast<int64_t>(distance)).c_str(),"2",0);
		std::cerr << "VirtualProtect failed." << std::endl;
		return false;
	}
	// 有一个符号位
	void *new_ret = nullptr;
	if (distance < INT32_MIN || distance > INT32_MAX)
	{
		new_ret = SearchAndFillJump(targetFunction, lpFunction);
		if (new_ret == nullptr)
		{
			std::cout << "搜索空闲内存失败" << std::endl;
			return false;
		}
		distance = reinterpret_cast<int64_t>(new_ret) - dwAddr - 5;
	}
	// 直接进行小跳转

	uint8_t call[] = {0xE8, 0x00, 0x00, 0x00, 0x00}; // 短CALL
	*reinterpret_cast<int32_t *>(&call[1]) = static_cast<int32_t>(distance);
	memcpy(targetFunction, call, sizeof(call));
	// 恢复原来的内存保护属性
	if (!VirtualProtect(targetFunction, 10, oldProtect, &oldProtect))
	{
		return false;
	}

	return true;
}
#elif defined(_LINUX_PLATFORM_)
bool Hook(uint64_t dwAddr, void * lpFunction)
{
	auto get_page_addr = [](void *addr) -> void * {
		return (void *)((uintptr_t)addr & ~(getpagesize() - 1));
	};
	void *targetFunction = reinterpret_cast<void *>(dwAddr);
	mprotect(get_page_addr(targetFunction), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC); // 设置内存可写
	int64_t distance = reinterpret_cast<int64_t>(lpFunction) - dwAddr - 5;
	void *new_ret = nullptr;
	if (distance < INT32_MIN || distance > INT32_MAX)
	{
		// new_ret = SearchAndFillJump(targetFunction, lpFunction);
		if (new_ret == nullptr)
		{
			// MessageBoxA(0, "error", "跳转失败", 0);
			return false;
		}
		distance = reinterpret_cast<int64_t>(new_ret) - dwAddr - 5;
	}
	uint8_t call[] = {0xE8, 0x00, 0x00, 0x00, 0x00}; // 短CALL
	*reinterpret_cast<int32_t *>(&call[1]) = static_cast<int32_t>(distance);
	memcpy(targetFunction, call, sizeof(call));
	mprotect(get_page_addr(targetFunction), getpagesize(), PROT_READ | PROT_EXEC); // 还原内存
	return true;
}

#endif
