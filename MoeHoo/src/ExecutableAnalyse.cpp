#include "ExecutableAnalyse.h"

std::vector<char> ReadFileToMemory(const std::string &filePath)
{
	std::ifstream file(filePath, std::ios::binary | std::ios::ate);
	if (!file)
	{
		throw std::runtime_error("无法打开文件");
	}
	size_t fileSize = file.tellg();
	std::vector<char> buffer(fileSize);
	file.seekg(0, std::ios::beg);
	file.read(buffer.data(), fileSize);
	return buffer;
}

size_t SearchHexPattern(const std::vector<char> &data, const std::string &hexPattern)
{
	std::string dataStr(data.begin(), data.end());
	size_t pos = dataStr.find(hexPattern);
	if (pos == std::string::npos)
	{
		throw std::runtime_error("未找到指定的十六进制序列");
	}
	return pos;
}

// 用于将模块基址转换为RVA
DWORD_PTR ModuleBaseToRVA(DWORD_PTR base, DWORD_PTR address)
{
	return address - base;
}

// 搜索特定十六进制模式的函数
DWORD_PTR SearchInModule(HMODULE module, const std::string &hexPattern)
{
	HANDLE processHandle = GetCurrentProcess();
	MODULEINFO modInfo;
	if (!GetModuleInformation(processHandle, module, &modInfo, sizeof(MODULEINFO)))
	{
		return 0;
	}
	std::vector<BYTE> pattern(hexPattern.begin(), hexPattern.end());
	// 在模块内存范围内搜索模式
	BYTE *start = static_cast<BYTE *>(modInfo.lpBaseOfDll);
	BYTE *end = start + modInfo.SizeOfImage - pattern.size();
	DWORD_PTR address = 0;

	for (BYTE *current = start; current < end; ++current)
	{
		if (std::equal(pattern.begin(), pattern.end(), current))
		{
			// 不需要rva 这处就是实际地址
			// rva = ModuleBaseToRVA(reinterpret_cast<DWORD_PTR>(modInfo.lpBaseOfDll), reinterpret_cast<DWORD_PTR>(current));
			// return rva;
			return reinterpret_cast<DWORD_PTR>(current);
		}
	}

	return 0;
}