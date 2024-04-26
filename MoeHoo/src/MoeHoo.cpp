#include <iostream>
#include <fstream>
#include <sstream>
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
int64_t hookptr;
int64_t hookorgptr;
typedef int64_t (*FuncPtr)(int64_t, char **);
std::mutex recvRkeyLock;
FuncPtr func;
// 没有做多线程安全与回调 可能大问题
int64_t recvRkey(int64_t a1, char **a2)
{
	printf("recvRkey: %s\n", *a2);
	recvRkeyLock.lock();
	rkey = *a2;
	int64_t ret = func(a1, a2);
	recvRkeyLock.unlock();
	return ret;
}

int64_t searchRkeyDownloadHook()
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
		{
			tokens.push_back(token);
		}

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
			std::string hexPattern_Before = "\xBE\x04\x00\x00\x00\xB9\x53\x00\x00\x00\x53\x55\x41\x52\x50\x41\x56\xE8";
			// 标准位置查找
			std::string hexPattern = "\x48\x8B\x1C\x24\x48\x89\xDF\x4C\x89\xE6\xE8";
			// 被调用函数特征
			std::string expecteduint8_ts = "\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x54\x53\x49\x89\xFC\xF6\x06\x01";
			int64_t address = 0;
			// 需要判断
			int64_t beforeOffect = SearchRangeAddressInModule(pmaps, hexPattern_Before, 0x1CB0001, 0x1CFFA80);
			// printf("beforeOffect: %lx\n", beforeOffect);
			if (beforeOffect <= 0)
				return 0;
			int64_t searchOffset = beforeOffect + 18 - pmaps->start();
			while (true)
			{
				address = SearchRangeAddressInModule(pmaps, hexPattern, searchOffset);
				// printf("address: %lx\n", address);
				if (address <= 0)
					return 0;
				address += 10;
				hookorgptr = GetFunctionAddress(address);
				// printf("hookorgptr: %lx\n", hookorgptr);
				for(int i = 0; i < 32; i++)
					printf("%02x ", reinterpret_cast<uint8_t *>(hookorgptr)[i]);
				if (std::equal(expecteduint8_ts.begin(), expecteduint8_ts.end(), reinterpret_cast<uint8_t *>(hookorgptr)))
					return address;

				// 获得的RVA在CALL前面 无法再次匹配 进一步搜索
				searchOffset = address - pmaps->start();
			}
		}
	}
	return 0;
#elif defined(_WIN_PLATFORM_)
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
	std::string hexPattern_Before = "\xBA\x04\x00\x00\x00\x49\x8B\xCF\xE8";
	// 标准位置查找
	std::string hexPattern = "\x48\x8D\x56\x28\x48\x8B\xCB\xE8";
	// 被调用函数特征
	std::string expecteduint8_ts = "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7C\x24\x18\x41\x56\x48\x83\xEC\x20\x45\x33\xC9\x0F\x57\xC0\x0F\x11\x01\x4C\x89\x49\x10";
	int64_t address = 0;
	// 需要判断
	int64_t beforeOffect = SearchRangeAddressInModule(wrapperModule, hexPattern_Before, 0x1CB0001, 0x1CFFA80);
	if (beforeOffect <= 0)
	{
		return 0;
	}
	int64_t searchOffset = beforeOffect + 8 - reinterpret_cast<int64_t>(modInfo.lpBaseOfDll);
	// 0x1CB0015;
	while (true)
	{
		address = SearchRangeAddressInModule(wrapperModule, hexPattern, searchOffset, 0x1CF0015);
		if (address <= 0)
			return 0;
		address += 7;
		hookorgptr = GetFunctionAddress(address);
		if (std::equal(expecteduint8_ts.begin(), expecteduint8_ts.end(), reinterpret_cast<uint8_t *>(hookorgptr)) == 0)
			return address;

		// 获得的RVA在CALL前面 无法再次匹配 进一步搜索
		searchOffset = address - reinterpret_cast<int64_t>(modInfo.lpBaseOfDll);
	}
	return address;
#endif
}

namespace demo
{
	napi_value HookRkey(napi_env env, napi_callback_info args)
	{
		napi_value greeting;
		napi_status status;
		// searchRkeyDownloadHook() CALL点处
		hookptr = searchRkeyDownloadHook();
		if (hookptr == 0 || hookorgptr == 0)
		{
			status = napi_create_string_utf8(env, "error search", NAPI_AUTO_LENGTH, &greeting);
			if (status != napi_ok)
				return nullptr;
			return greeting;
		}
		bool ret = Hook(hookptr, (void *)recvRkey);
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
