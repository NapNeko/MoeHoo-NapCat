#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <psapi.h>

std::vector<char> ReadFileToMemory(const std::string &filePath);
size_t SearchHexPattern(const std::vector<char> &data, const std::string &hexPattern);
INT64 SearchInModuleRange(HMODULE module, const std::string &hexPattern, INT64 searchStartRVA, INT64 searchEndRVA);