#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <node_api.h>

std::vector<char> ReadFileToMemory(const std::string &filePath);
size_t SearchHexPattern(const std::vector<char> &data, const std::string &hexPattern);