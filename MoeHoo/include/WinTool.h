#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <psapi.h>

// 从wrapper模块里面rdata段内存搜索某文本 返回字符串地址
void SearchStringAddressForMemory(){

}
// 从某模块里面某位置搜索特征出地址
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