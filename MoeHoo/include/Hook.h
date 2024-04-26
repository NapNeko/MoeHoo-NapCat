#include <string>
// 跨平台兼容个灯
#include <iostream>

#if defined(_WIN_PLATFORM_)
#include <Windows.h>
#elif defined(_LINUX_PLATFORM_)
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

void *GetCallAddress(uint8_t *ptr)
{
	// 读取操作码
	if (ptr[0] != 0xE8)
	{
		std::cerr << "Not a call instruction!" << std::endl;
		return 0;
	}

	// 读取相对偏移量
	int32_t relativeOffset = *reinterpret_cast<int32_t *>(ptr + 1);

	// 计算函数地址
	uint8_t *callAddress = ptr + 5; // call 指令占 5 个字节
	void *functionAddress = callAddress + relativeOffset;

	return reinterpret_cast<void *>(functionAddress);
}
#if defined(_WIN_PLATFORM_)
// 实现搜索某指针上下2GB的可用内存 进行填充远跳JMP 填充完成返回填充内存首地址 失败返回nullptr
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
bool Hook(uint8_t *callAddr, void *lpFunction)
{
	uint64_t startAddr = reinterpret_cast<uint64_t>(callAddr) + 5;
	int64_t distance = reinterpret_cast<uint64_t>(lpFunction) - startAddr;
	printf("Hooking %p to %p, distance: %lld\n", callAddr, lpFunction, distance);
	DWORD oldProtect;
	if (!VirtualProtect(callAddr, 10, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		// MessageBoxA(0,std::to_string(static_cast<int64_t>(distance)).c_str(),"2",0);
		std::cerr << "VirtualProtect failed." << std::endl;
		return false;
	}
	if (distance < INT32_MIN || distance > INT32_MAX)
	{
		void *new_ret = SearchAndFillJump(callAddr, lpFunction);
		if (new_ret == nullptr)
		{
			std::cout << "搜索空闲内存失败" << std::endl;
			return false;
		}
		distance = reinterpret_cast<int64_t>(new_ret) - startAddr;
		printf("new_ret: %p, new_distance: %lld\n", new_ret, distance);
	}
	// 直接进行小跳转

	memcpy(callAddr + 1, reinterpret_cast<int32_t *>(&distance), 4); // 修改 call 地址
	// 恢复原来的内存保护属性
	return VirtualProtect(callAddr, 10, oldProtect, nullptr);
}
#elif defined(_LINUX_PLATFORM_)
void *SearchAndFillJump(void *baseAddress, void *targetAddress)
{
	unsigned char jumpInstruction[14] = {
		0x49, 0xBB,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x41, 0xFF, 0xE3};

	memcpy(&jumpInstruction[2], &targetAddress, sizeof(targetAddress));

	// Iterate through memory regions
	char *searchStart = static_cast<char *>(baseAddress) - 0x80000000;
	char *searchEnd = static_cast<char *>(baseAddress) + 0x80000000;

	while (searchStart < searchEnd)
	{
		// Use mmap to query memory information
		struct stat mbi;
		if (mmap(searchStart, sizeof(mbi), PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
			break;

		// Check if the region is writable
		if (mbi.st_mode & S_IWUSR)
		{
			if (mbi.st_size >= sizeof(jumpInstruction))
			{
				memcpy(searchStart, jumpInstruction, sizeof(jumpInstruction));
				return searchStart;
			}
		}
		searchStart += mbi.st_size;
	}
	return nullptr;
}
bool Hook(uint8_t *callAddr, void *lpFunction)
{
	uint64_t startAddr = reinterpret_cast<uint64_t>(callAddr) + 5;
	int64_t distance = reinterpret_cast<int64_t>(lpFunction) - startAddr;
	printf("Hooking %p to %p, distance: %ld\n", callAddr, lpFunction, distance);
	auto get_page_addr = [](void *addr) -> void *
	{
		return (void *)((uintptr_t)addr & ~(getpagesize() - 1));
	};
	if (mprotect(get_page_addr(callAddr), 2 * getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) // 设置内存可写 两倍 pagesize 防止处于页边界
		return false;
	printf("mprotect\n");
	void *new_ret = nullptr;
	if (distance < INT32_MIN || distance > INT32_MAX)
	{
		if ((new_ret = SearchAndFillJump(callAddr, lpFunction)) == nullptr)
		{
			printf("跳转失败");
			return false;
		}
		distance = reinterpret_cast<int64_t>(new_ret) - startAddr;
		printf("new_ret: %p, new_distance: %ld\n", new_ret, distance);
	}
	memcpy(callAddr + 1, reinterpret_cast<int32_t *>(&distance), 4); // 修改 call 地址
	// for (int i = 0; i < 10; i++)
	// 	printf("%02x ", reinterpret_cast<uint8_t *>(callAddr)[i]);
	return mprotect(get_page_addr(callAddr), 2 * getpagesize(), PROT_READ | PROT_EXEC) == -1; // 还原内存
}

#endif
