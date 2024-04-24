#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#ifdef _WIN_PLATFORM_
#include <Windows.h>
#include <psapi.h>
#elif _LINUX_PLATFORM_
#endif

std::vector<char> ReadFileToMemory(const std::string &filePath);
size_t SearchHexPattern(const std::vector<char> &data, const std::string &hexPattern);
#ifdef _LINUX_PLATFORM_
INT64 SearchRangeAddressInModule(void *module, const std::string &hexPattern, INT64 searchStartRVA = 0, INT64 searchEndRVA = 0);
#elif _WIN_PLATFORM_
INT64 SearchRangeAddressInModule(HMODULE module, const std::string &hexPattern, INT64 searchStartRVA = 0, INT64 searchEndRVA = 0);
#endif