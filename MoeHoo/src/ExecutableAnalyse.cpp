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
INT64 ModuleBaseToRVA(INT64 base, INT64 address)
{
	return address - base;
}
// 从某模块里面某位置搜索特征出地址
#ifdef _LINUX_PLATFORM_
INT64 SearchRangeAddressInModule(void* module, const std::string& hexPattern, INT64 searchStartRVA, INT64 searchEndRVA)
{
    dl_info info;
    if (dladdr(module, &info) == 0)
    {
        return 0;
    }

    std::vector<BYTE> pattern;
    for (size_t i = 0; i < hexPattern.length(); i += 2)
    {
        pattern.push_back(static_cast<BYTE>(std::stoi(hexPattern.substr(i, 2), nullptr, 16)));
    }

    BYTE* base = static_cast<BYTE*>(info.dli_fbase);
    BYTE* searchStart = base + searchStartRVA;
    if (searchEndRVA == 0)
    {
        // 如果留空表示搜索到结束
        searchEndRVA = info.dli_memsz;
    }
    BYTE* searchEnd = base + searchEndRVA;

    // 确保搜索范围有效
    if (searchStart >= base && searchEnd <= base + info.dli_memsz && searchStart < searchEnd)
    {
        for (BYTE* current = searchStart; current < searchEnd; ++current)
        {
            if (std::equal(pattern.begin(), pattern.end(), current))
            {
                return reinterpret_cast<INT64>(current);
            }
        }
    }

    return 0;
}
#elif _WIN_PLATFORM_
INT64 SearchRangeAddressInModule(HMODULE module, const std::string &hexPattern, INT64 searchStartRVA, INT64 searchEndRVA)
{
    HANDLE processHandle = GetCurrentProcess();
    MODULEINFO modInfo;
    if (!GetModuleInformation(processHandle, module, &modInfo, sizeof(MODULEINFO)))
    {
        return 0;
    }
    std::vector<BYTE> pattern(hexPattern.begin(), hexPattern.end());
    // 在模块内存范围内搜索模式
    BYTE *base = static_cast<BYTE *>(modInfo.lpBaseOfDll);
    BYTE *searchStart = base + searchStartRVA;
    if (searchEndRVA == 0)
    {
        // 如果留空表示搜索到结束
        searchEndRVA = modInfo.SizeOfImage;
    }
    BYTE *searchEnd = base + searchEndRVA;
    INT64 address = 0;

    // 确保搜索范围有效
    if (searchStart >= base && searchEnd <= base + modInfo.SizeOfImage && searchStart < searchEnd)
    {
        for (BYTE *current = searchStart; current < searchEnd; ++current)
        {
            if (std::equal(pattern.begin(), pattern.end(), current))
            {
                return reinterpret_cast<INT64>(current);
            }
        }
    }

    return 0;
}
#endif
