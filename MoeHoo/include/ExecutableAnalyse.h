#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#if defined(_WIN_PLATFORM_)
#include <Windows.h>
#include <psapi.h>
#elif defined(_LINUX_PLATFORM_)
#include <proc_maps.h>
#endif

// std::vector<char> ReadFileToMemory(const std::string &filePath);
size_t SearchHexPattern(const std::vector<char> &data, const std::string &hexPattern);
#if defined(_LINUX_PLATFORM_)
int64_t SearchRangeAddressInModule(std::shared_ptr<hak::proc_maps> module, const std::string &hexPattern, int64_t searchStartRVA = 0, int64_t searchEndRVA = 0);
#elif defined(_WIN_PLATFORM_)
int64_t SearchRangeAddressInModule(HMODULE module, const std::string &hexPattern, int64_t searchStartRVA = 0, int64_t searchEndRVA = 0);
#endif