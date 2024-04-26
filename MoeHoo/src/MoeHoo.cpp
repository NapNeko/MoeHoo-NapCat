#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <node_api.h>
#include "ExecutableAnalyse.h"
#include <Hook.h>
#include <mutex>
// include ${CMAKE_SOURCE_DIR}/node_modules/node-api-headers/include

// PE文件静态方法
// PE内存搜索方案
typedef uint64_t (*FuncPtr)(uint64_t, uint64_t);
uint64_t callptr;
FuncPtr orifuncptr;

std::mutex recvRkeyLock;
std::string rkey = "";
// 没有做多线程安全与回调 可能大问题
uint64_t recvRkey(uint64_t a1, uint64_t a2)
{
	recvRkeyLock.lock();
#if defined(_LINUX_PLATFORM_)
	rkey = *reinterpret_cast<const char **>(a2 + 16);
#elif defined(_WIN_PLATFORM_)
	rkey = *reinterpret_cast<const char **>(a2);
#endif
	printf("recvRkey: %s\n", rkey.c_str());
	int64_t ret = orifuncptr(a1, a2);
	recvRkeyLock.unlock();
	return ret;
}

std::pair<uint64_t, FuncPtr> searchRkeyDownloadHook()
{
#if defined(_LINUX_PLATFORM_)
	std::ifstream maps(std::string("/proc/self/maps"));
	std::string line;
	bool last_is_cd = false;
	while (getline(maps, line))
	{
		std::istringstream iss(line);
		std::vector<std::string> tokens;
		std::string token;

		while (getline(iss, token, ' '))
			tokens.push_back(token);

		auto address = tokens[0];
		std::string::size_type pos = address.find('-');
		uint64_t start_addr = std::stol(address.substr(0, pos), nullptr, 16);
		uint64_t end_addr = std::stol(address.substr(pos + 1), nullptr, 16);
		auto pmaps = std::make_shared<hak::proc_maps>(start_addr, end_addr);
		auto perms = tokens[1];
		pmaps->readable = perms[0] == 'r';
		pmaps->writable = perms[1] == 'w';
		pmaps->executable = perms[2] == 'x';
		pmaps->is_private = perms[3] == 'p';
		pmaps->offset = std::stoll(tokens[2], nullptr, 16);
		if (tokens.size() > 5)
			for (int i = 5; i < tokens.size(); i++)
				pmaps->module_name += tokens[i];
		// printf("start: %lx, end: %lx, offset: %x, module_name: %s\n", pmaps->start(), pmaps->end(), pmaps->offset, pmaps->module_name.c_str());
		if (pmaps->module_name.find("wrapper.node") != std::string::npos && pmaps->executable && pmaps->readable)
		{
			uint8_t hexPattern_Before[] = {0xBE, 0x04, 0x00, 0x00, 0x00, 0xB9, 0x53, 0x00, 0x00, 0x00, 0x53, 0x55, 0x41, 0x52, 0x50, 0x41, 0x56, 0xE8};
			std::vector<uint8_t> hexPattern_Before_v(hexPattern_Before, hexPattern_Before + sizeof(hexPattern_Before));
			// 标准位置查找
			uint8_t hexPattern[] = {0x48, 0x8B, 0x1C, 0x24, 0x48, 0x89, 0xDF, 0x4C, 0x89, 0xE6, 0xE8};
			std::vector<uint8_t> hexPattern_v(hexPattern, hexPattern + sizeof(hexPattern));
			// 被调用函数特征
			uint8_t expected[] = {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x53, 0x49, 0x89, 0xFC, 0xF6, 0x06, 0x01, 0x75, 0x1A, 0x48, 0x8B, 0x46, 0x10, 0x49, 0x89, 0x44, 0x24, 0x10, 0x0F, 0x10, 0x06, 0x41, 0x0F, 0x11, 0x04, 0x24, 0x5B, 0x41, 0x5C, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3, 0x4C, 0x8B, 0x76, 0x08, 0x4C, 0x8B, 0x7E, 0x10, 0x49, 0x83, 0xFE, 0x16, 0x76, 0x44, 0x49, 0x83, 0xFE, 0xF0, 0x73, 0x4B, 0x49, 0x8D, 0x5E, 0x10, 0x48, 0x83, 0xE3, 0xF0, 0x48, 0x89, 0xDF, 0xE8, 0x1F, 0x36, 0x78, 0x03, 0x49, 0x89, 0x44, 0x24, 0x10, 0x48, 0x83, 0xCB, 0x01, 0x49, 0x89, 0x1C, 0x24, 0x4D, 0x89, 0x74, 0x24, 0x08, 0x49, 0x89, 0xC4, 0x49, 0xFF, 0xC6, 0x4C, 0x89, 0xE7, 0x4C, 0x89, 0xFE, 0x4C, 0x89, 0xF2, 0x5B, 0x41, 0x5C, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xE9, 0x91, 0x36, 0x78, 0x03, 0x43, 0x8D, 0x04, 0x36, 0x41, 0x88, 0x04, 0x24, 0x49, 0xFF, 0xC4, 0xEB, 0xDA, 0x4C, 0x89, 0xE7, 0xE8, 0x2C, 0x87, 0x7C, 0xFF};
			std::vector<uint8_t> expected_v(expected, expected + sizeof(expected));

			// 需要判断
			uint64_t beforeOffect = SearchRangeAddressInModule(pmaps, hexPattern_Before_v);
			// printf("beforeOffect: %lx\n", beforeOffect);
			if (beforeOffect == 0)
				return std::make_pair(0, nullptr);
			uint64_t searchOffset = beforeOffect + sizeof(hexPattern_Before) - 1 - pmaps->start();
			while (true)
			{
				uint64_t address = SearchRangeAddressInModule(pmaps, hexPattern_v, searchOffset);
				// printf("address: %lx\n", address);
				if (address == 0)
					return std::make_pair(0, nullptr);
				address += sizeof(hexPattern) - 1;
				FuncPtr funcptr = reinterpret_cast<FuncPtr>(GetCallAddress(reinterpret_cast<uint8_t *>(address)));
				// printf("funcptr: %p\n", funcptr);
				if (std::equal(expected_v.begin(), expected_v.end(), reinterpret_cast<uint8_t *>(funcptr)))
					return std::make_pair(address, funcptr);

				// 获得的RVA在CALL前面 无法再次匹配 进一步搜索
				searchOffset = address - pmaps->start();
			}
		}
	}
	return std::make_pair(0, nullptr);
	;
#elif defined(_WIN_PLATFORM_)
	HMODULE wrapperModule = GetModuleHandleW(L"wrapper.node"); // 内存
	MODULEINFO modInfo;
	if (wrapperModule == NULL)
	{
		return std::make_pair(0, nullptr);
	}
	if (!GetModuleInformation(GetCurrentProcess(), wrapperModule, &modInfo, sizeof(MODULEINFO)))
	{
		return std::make_pair(0, nullptr);
	}
	uint8_t hexPattern_Before[] = {0xBA, 0x04, 0x00, 0x00, 0x00, 0x49, 0x8B, 0xCF, 0xE8};
	std::vector<uint8_t> hexPattern_Before_v(hexPattern_Before, hexPattern_Before + sizeof(hexPattern_Before));
	// 标准位置查找
	uint8_t hexPattern[] = {0x48, 0x8D, 0x56, 0x28, 0x48, 0x8B, 0xCB, 0xE8};
	std::vector<uint8_t> hexPattern_v(hexPattern, hexPattern + sizeof(hexPattern));
	// 被调用函数特征
	uint8_t expected[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x45, 0x33, 0xC9, 0x0F, 0x57, 0xC0, 0x0F, 0x11, 0x01, 0x4C, 0x89, 0x49, 0x10};
	std::vector<uint8_t> expected_v(expected, expected + sizeof(expected));

	// 需要判断
	uint64_t beforeOffect = SearchRangeAddressInModule(wrapperModule, hexPattern_Before_v, 0x1CB0001, 0x1CFFA80);
	// printf("beforeOffect: %llx\n", beforeOffect);
	if (beforeOffect <= 0)
		return std::make_pair(0, nullptr);

	int64_t searchOffset = beforeOffect + sizeof(hexPattern_Before) - 1 - reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
	// 0x1CB0015;
	while (true)
	{
		uint64_t address = SearchRangeAddressInModule(wrapperModule, hexPattern_v, searchOffset, 0x1CF0015);
		// printf("address: %llx\n", address);
		if (address == 0)
			return std::make_pair(0, nullptr);
		address += sizeof(hexPattern) - 1;
		FuncPtr funcptr = reinterpret_cast<FuncPtr>(GetCallAddress(reinterpret_cast<uint8_t *>(address)));
		// printf("funcptr: %p\n", funcptr);
		if (std::equal(expected_v.begin(), expected_v.end(), reinterpret_cast<uint8_t *>(funcptr)))
			return std::make_pair(address, funcptr);

		// 获得的RVA在CALL前面 无法再次匹配 进一步搜索
		searchOffset = address - reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
	}
	return std::make_pair(0, nullptr);
#endif
}

namespace demo
{
	napi_value HookRkey(napi_env env, napi_callback_info args)
	{
		napi_value greeting;
		napi_status status;
		std::tie(callptr, orifuncptr) = searchRkeyDownloadHook();
		if (callptr == 0 || orifuncptr == nullptr)
		{
			status = napi_create_string_utf8(env, "error search", NAPI_AUTO_LENGTH, &greeting);
			if (status != napi_ok)
				return nullptr;
			return greeting;
		}
		if (!Hook(reinterpret_cast<uint8_t *>(callptr), (void *)recvRkey))
		{
			status = napi_create_string_utf8(env, "error hook", NAPI_AUTO_LENGTH, &greeting);
			if (status != napi_ok)
				return nullptr;
			return greeting;
		}
		status = napi_create_string_utf8(env, std::to_string(callptr).c_str(), NAPI_AUTO_LENGTH, &greeting);
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
		status = napi_create_function(env, nullptr, 0, HookRkey, nullptr, &fn);
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
