#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <node_api.h>
#include "MoeHoo.h"
#include "ExecutableAnalyse.h"
#include <Hook.h>
#include <mutex>
static std::string rkey = "";
// include ${CMAKE_SOURCE_DIR}/node_modules/node-api-headers/include

// PE文件静态方法
// PE内存搜索方案
INT64 hookptr;
INT64 hookorgptr;
typedef INT64 (*FuncPtr)(INT64, char **);
std::mutex recvRkeyLock;
FuncPtr func;
// 没有做多线程安全与回调 可能大问题
INT64 recvRkey(INT64 a1, char **a2)
{
	//MessageBoxA(0, "", *a2, 0);
	recvRkeyLock.lock();
	rkey = *a2;
	INT64 ret = func(a1, a2);
	recvRkeyLock.unlock();
	return ret;
}

INT64 searchRkeyDownloadHook()
{
#ifdef _LINUX_PLATFORM_
#elif _WIN_PLATFORM_
	HMODULE wrapperModule = GetModuleHandleW(L"wrapper.node"); // 内存
	MODULEINFO modInfo;
	if (wrapperModule == NULL)
	{
		return 0;
	}
	if (!GetModuleInformation(GetCurrentProcess(), wrapperModule, &modInfo, sizeof(MODULEINFO)))
	{
		return 0;
	}
	// 前置位置查找
	// \xBE\x04\x00\x00\x00\xB9\x53\x00\x00\x00\x53\x55\x41\x52\x50\x41\x56\xE8 Linux 前置点
	// \x48\x8B\x1C\x24\x48\x89\xDF\x4C\x89\xE6\xE8 Linux 标准位置
	// \x55\x48\x89\xE5\x41\x57\x41\x56\x41\x54\x53\x49\x89\xFC\xF6\x06\x01 Linux 被调用函数特征
	std::string hexPattern_Before = "\xBA\x04\x00\x00\x00\x49\x8B\xCF\xE8";
	// 标准位置查找
	std::string hexPattern = "\x48\x8D\x56\x28\x48\x8B\xCB\xE8";
	// 被调用函数特征
	std::string expectedBytes = "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7C\x24\x18\x41\x56\x48\x83\xEC\x20\x45\x33\xC9\x0F\x57\xC0\x0F\x11\x01\x4C\x89\x49\x10";
	INT64 address = 0;
	// 需要判断
	INT64 beforeOffect = SearchRangeAddressInModule(wrapperModule, hexPattern_Before, 0x1CB0001, 0x1CFFA80);
	if (beforeOffect <= 0)
	{
		return 0;
	}
	INT64 searchOffset = beforeOffect + 0x8 - reinterpret_cast<INT64>(modInfo.lpBaseOfDll);
	// 0x1CB0015;
	bool done = false;
	while (!done)
	{
		address = SearchRangeAddressInModule(wrapperModule, hexPattern, searchOffset, 0x1CF0015) + 0x7;
		// MessageBoxA(0, std::to_string((UINT64)address).c_str(), std::to_string((UINT64)searchOffset).c_str(), 0);
		if (address <= 0)
		{
			done = true;
			break;
		}
		hookorgptr = GetFunctionAddress(address);
		BYTE *hookorgptr2 = reinterpret_cast<BYTE *>(hookorgptr);
		// MessageBoxA(0, std::to_string(hookorgptr).c_str(), std::to_string(std::equal(expectedBytes.begin(), expectedBytes.end(), hookorgptr2)).c_str(), 0);
		if (std::equal(expectedBytes.begin(), expectedBytes.end(), hookorgptr2) == 0)
		{
			done = true;
			break;
		}

		// 获得的RVA在CALL前面 无法再次匹配 进一步搜索
		searchOffset = address - reinterpret_cast<INT64>(modInfo.lpBaseOfDll);
	}
	return address;
#endif
}

namespace demo
{

	napi_value Method(napi_env env, napi_callback_info args)
	{
		napi_value greeting;
		napi_status status;
		// searchRkeyDownloadHook() CALL点处
		hookptr = searchRkeyDownloadHook();
		// MessageBoxA(0, std::to_string(static_cast<INT64>(hookptr)).c_str(), "1", 0);
		if (hookptr == 0)
		{
			status = napi_create_string_utf8(env, "error search", NAPI_AUTO_LENGTH, &greeting);
			if (status != napi_ok)
				return nullptr;
			return greeting;
		}
		func = reinterpret_cast<FuncPtr>(hookorgptr);
		if (hookorgptr == 0)
		{
			status = napi_create_string_utf8(env, "error search", NAPI_AUTO_LENGTH, &greeting);
			if (status != napi_ok)
				return nullptr;
			return greeting;
		}
		bool ret = Hook(hookptr, recvRkey);
		if (!ret)
		{
			status = napi_create_string_utf8(env, "error hook", NAPI_AUTO_LENGTH, &greeting);
			if (status != napi_ok)
				return nullptr;
			return greeting;
		}
		status = napi_create_string_utf8(env, std::to_string(hookptr).c_str(), NAPI_AUTO_LENGTH, &greeting);
		if (status != napi_ok)
			return nullptr;
		return greeting;
	}
	napi_value GetRkey(napi_env env, napi_callback_info args)
	{
		napi_value greeting;
		napi_status status;
		// searchRkeyDownloadHook() CALL点处
		status = napi_create_string_utf8(env, rkey.c_str(), NAPI_AUTO_LENGTH, &greeting);
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
		status = napi_set_named_property(env, exports, "HookRkey", fn);
		if (status != napi_ok)
			return nullptr;
		status = napi_create_function(env, nullptr, 0, GetRkey, nullptr, &fn);
		if (status != napi_ok)
			return nullptr;
		status = napi_set_named_property(env, exports, "GetRkey", fn);
		if (status != napi_ok)
			return nullptr;
		return exports;
	}

	NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

}

// int def_test()
// {
// 	try
// 	{
// 		// 读取PE文件到内存
// 		std::vector<char> PEData(ReadFileToMemory("E:\\APPD\\NTQQ\\resources\\app\\versions\\9.9.9-22961\\wrapper.node"));
// 		std::string hexPattern = "\xE8\x62\x01\x8F\xFE";
// 		size_t patternPos = SearchHexPattern(PEData, hexPattern);

// 		std::cout << "十六进制序列的文件偏移位置: " << std::hex << patternPos << std::endl;

// 		// 计算RVA
// 		// .text 代码节的RVA为0x1000，文件偏移为0x400
// 		size_t codeSectionRVA = 0x1000;
// 		size_t codeSectionFOA = 0x400;
// 		size_t rva = codeSectionRVA + (patternPos - codeSectionFOA);

// 		std::cout << "十六进制序列的RVA: " << std::hex << rva << std::endl;
// 		std::cout << "十六进制序列的Hook点:" << std::hex << rva - 0x3 << std::endl;
// 	}
// 	catch (const std::exception &e)
// 	{
// 		std::cerr << "错误: " << e.what() << std::endl;
// 	}
// 	system("pause");
// 	return 0;
// }
