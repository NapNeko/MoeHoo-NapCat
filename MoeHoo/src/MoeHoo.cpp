#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "MoeHoo.h"
#include <node_api.h>
//${CMAKE_SOURCE_DIR}/node_modules/node-api-headers/include
namespace demo {

napi_value Method(napi_env env, napi_callback_info args) {
  napi_value greeting;
  napi_status status;

  status = napi_create_string_utf8(env, "world", NAPI_AUTO_LENGTH, &greeting);
  if (status != napi_ok) return nullptr;
  return greeting;
}

napi_value init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;

  status = napi_create_function(env, nullptr, 0, Method, nullptr, &fn);
  if (status != napi_ok) return nullptr;

  status = napi_set_named_property(env, exports, "hello", fn);
  if (status != napi_ok) return nullptr;
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

}  // namespace demo

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

int def_test()
{
	try
	{
		// 读取PE文件到内存
		std::vector<char> PEData(ReadFileToMemory("E:\\APPD\\NTQQ\\resources\\app\\versions\\9.9.9-22961\\wrapper.node"));
		std::string hexPattern = "\xE8\x62\x01\x8F\xFE";
		size_t patternPos = SearchHexPattern(PEData, hexPattern);

		std::cout << "十六进制序列的文件偏移位置: " << std::hex << patternPos << std::endl;

		// 计算RVA
		// .text 代码节的RVA为0x1000，文件偏移为0x400
		size_t codeSectionRVA = 0x1000;
		size_t codeSectionFOA = 0x400;
		size_t rva = codeSectionRVA + (patternPos - codeSectionFOA);

		std::cout << "十六进制序列的RVA: " << std::hex << rva << std::endl;
		std::cout << "十六进制序列的Hook点:" << std::hex << rva - 0x3 << std::endl;
	}
	catch (const std::exception &e)
	{
		std::cerr << "错误: " << e.what() << std::endl;
	}
	system("pause");
	return 0;
}
