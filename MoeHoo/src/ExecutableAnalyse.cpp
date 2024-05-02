#include "ExecutableAnalyse.h"

// std::vector<char> ReadFileToMemory(const std::string &filePath)
// {
// 	std::ifstream file(filePath, std::ios::binary | std::ios::ate);
// 	if (!file)
// 	{
// 		throw std::runtime_error("无法打开文件");
// 	}
// 	size_t fileSize = file.tellg();
// 	std::vector<char> buffer(fileSize);
// 	file.seekg(0, std::ios::beg);
// 	file.read(buffer.data(), fileSize);
// 	return buffer;
// }

// size_t SearchHexPattern(const std::vector<char> &data, const std::string &hexPattern)
// {
// 	std::string dataStr(data.begin(), data.end());
// 	size_t pos = dataStr.find(hexPattern);
// 	if (pos == std::string::npos)
// 	{
// 		throw std::runtime_error("未找到指定的十六进制序列");
// 	}
// 	return pos;
// }
// 用于将模块基址转换为RVA
// int64_t ModuleBaseToRVA(int64_t base, int64_t address)
// {
//     return address - base;
// }

// 从某模块里面某位置搜索特征出地址
#if defined(_LINUX_PLATFORM_)
uint64_t SearchRangeAddressInModule(std::shared_ptr<hak::proc_maps> module, const std::vector<uint8_t> &pattern, uint64_t searchStartRVA, uint64_t searchEndRVA)
{
    uint8_t *base = reinterpret_cast<uint8_t *>(module->start());
    uint8_t *searchStart = base + searchStartRVA;
    uint8_t *searchEnd;
    if (searchEndRVA == 0)
        searchEnd = reinterpret_cast<uint8_t *>(module->end());
    else
        searchEnd = base + searchEndRVA;

    // 确保搜索范围有效
    if (searchEnd > reinterpret_cast<uint8_t *>(module->end())){
        printf("out of moudle end");
        searchEnd = reinterpret_cast<uint8_t *>(module->end());
    }
    for (uint8_t *current = searchStart; current < searchEnd; ++current)
        if (std::equal(pattern.begin(), pattern.end(), current))
            return reinterpret_cast<int64_t>(current);

    return 0;
}
#elif defined(_WIN_PLATFORM_)
uint64_t SearchRangeAddressInModule(HMODULE module, const std::vector<uint8_t> &pattern, uint64_t searchStartRVA, uint64_t searchEndRVA)
{
    HANDLE processHandle = GetCurrentProcess();
    MODULEINFO modInfo;
    if (!GetModuleInformation(processHandle, module, &modInfo, sizeof(MODULEINFO)))
    {
        return 0;
    }
    // 在模块内存范围内搜索模式
    uint8_t *base = static_cast<uint8_t *>(modInfo.lpBaseOfDll);
    uint8_t *searchStart = base + searchStartRVA;
    if (searchEndRVA == 0)
    {
        // 如果留空表示搜索到结束
        searchEndRVA = modInfo.SizeOfImage;
    }
    uint8_t *searchEnd = base + searchEndRVA;

    // 确保搜索范围有效
    if (searchStart >= base && searchEnd <= base + modInfo.SizeOfImage)
        for (uint8_t *current = searchStart; current < searchEnd; ++current)
            if (std::equal(pattern.begin(), pattern.end(), current))
                return reinterpret_cast<uint64_t>(current);

    return 0;
}
#endif
