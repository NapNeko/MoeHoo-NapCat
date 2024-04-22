#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <node_api.h>
#include "MoeHoo.h"
#include "ExecutableAnalyse.h"

// include ${CMAKE_SOURCE_DIR}/node_modules/node-api-headers/include

// PE文件静态方法
// PE内存搜索方案
DWORD_PTR searchRkeyDownloadHook()
{
	HMODULE wrapperModule = GetModuleHandleW(L"wrapper.node"); // 内存
	if (wrapperModule == NULL)
		return 0;
	std::string hexPattern = "\x48\x8D\x56\x28\x48\x8B\xCB";
	DWORD_PTR address = SearchInModule(wrapperModule, hexPattern);
	return address;
}

namespace demo
{

	napi_value Method(napi_env env, napi_callback_info args)
	{
		napi_value greeting;
		napi_status status;
		//searchRkeyDownloadHook() CALL点处
		status = napi_create_string_utf8(env, std::to_string(searchRkeyDownloadHook()).c_str(), NAPI_AUTO_LENGTH, &greeting);
		if (status != napi_ok)
			return nullptr;
		return greeting;
	}
	napi_value init(napi_env env, napi_value exports)
	{
		napi_status status;
		napi_value fn;

		status = napi_create_function(env, nullptr, 0, Method, nullptr, &fn);
		if (status != napi_ok)
			return nullptr;

		status = napi_set_named_property(env, exports, "hello", fn);
		if (status != napi_ok)
			return nullptr;
		return exports;
	}

	NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

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
