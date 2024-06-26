#include <node_api.h>
#include <mutex>
#include <map>
#include "ExecutableAnalyse.h"
#include "Hook.h"

// include ${CMAKE_SOURCE_DIR}/node_modules/node-api-headers/include

#if defined(_WIN_PLATFORM_)
#if defined(_X64_ARCH_)
std::map<std::string, std::pair<uint64_t, uint64_t>> addrMap = {
	{"9.9.9-23361", {0x1cd6359, 0x5c0310}}};
#endif
#elif defined(_LINUX_PLATFORM_)
#if defined(_X64_ARCH_)
std::map<std::string, std::pair<uint64_t, uint64_t>> addrMap = {
	{"3.2.7-22868", {0x37ce44c, 0x2255d00}},
	{"3.2.7-23159", {0x37d499c, 0x225a000}},
	{"3.2.7-23361", {0x37E291C, 0x2262070}}};
#endif
#endif
// Rkey 拦截点函数签名
typedef uint64_t (*FuncPtr)(uint64_t, uint64_t);
uint64_t callptr = 0;
FuncPtr orifuncptr = nullptr;
std::mutex recvRkeyLock;
std::string rkey = "";
uint64_t recvRkey(uint64_t a1, uint64_t a2)
{
	recvRkeyLock.lock();
#if defined(_LINUX_PLATFORM_)
	rkey = *reinterpret_cast<const char **>(a2 + 16);
#elif defined(_WIN_PLATFORM_)
	rkey = *reinterpret_cast<const char **>(a2);
#endif
	// printf("recvRkey: %s\n", rkey.c_str());
	int64_t ret = orifuncptr(a1, a2);
	recvRkeyLock.unlock();
	return ret;
}
std::pair<uint64_t, FuncPtr> searchRkeyByTable(std::string version)
{
	auto it = addrMap.find(version);
	if (it == addrMap.end())
		return std::make_pair(0, nullptr);
#if defined(_LINUX_PLATFORM_)
	auto pmap = hak::get_maps();
	do
	{
		// printf("start: %lx, end: %lx, offset: %x, module_name: %s\n", pmap->start(), pmap->end(), pmap->offset, pmap->module_name.c_str());
		if (pmap->module_name.find("wrapper.node") != std::string::npos && pmap->offset == 0)
			return std::make_pair(pmap->start() + it->second.first, reinterpret_cast<FuncPtr>(pmap->start() + it->second.second));
	} while ((pmap = pmap->next()) != nullptr);
	return std::make_pair(0, nullptr);
#elif defined(_WIN_PLATFORM_)
	HMODULE wrapperModule = GetModuleHandleW(L"wrapper.node"); // 内存
	MODULEINFO modInfo;
	if (wrapperModule == NULL || !GetModuleInformation(GetCurrentProcess(), wrapperModule, &modInfo, sizeof(MODULEINFO)))
		return std::make_pair(0, nullptr);

	return std::make_pair(reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll) + it->second.first, reinterpret_cast<FuncPtr>(reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll) + it->second.second));
#endif
}
std::pair<uint64_t, FuncPtr> searchRkeyByMemory()
{
#if defined(_LINUX_PLATFORM_)
	auto pmap = hak::get_maps();

	uint64_t base = 0;
	auto pmap2 = pmap;
	do
	{
		if (pmap2->module_name.find("wrapper.node") != std::string::npos && pmap2->offset == 0)
		{
			base = pmap2->start();
			break;
		}
	} while ((pmap2 = pmap2->next()) != nullptr);

	do
	{
		// printf("start: %lx, end: %lx, offset: %x, module_name: %s\n", pmap->start(), pmap->end(), pmap->offset, pmap->module_name.c_str());
		if (pmap->module_name.find("wrapper.node") != std::string::npos && pmap->executable && pmap->readable)
		{
			// CALL点前特征
			uint8_t hexPattern[] = {0x48, 0x8B, 0x1C, 0x24, 0x48, 0x89, 0xDF, 0x4C, 0x89, 0xE6, 0xE8};
			std::vector<uint8_t> hexPattern_v(hexPattern, hexPattern + sizeof(hexPattern));
			// 被调用函数特征
			uint8_t expected[] = {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x53, 0x49, 0x89, 0xFC, 0xF6, 0x06, 0x01, 0x75, 0x1A, 0x48, 0x8B, 0x46, 0x10, 0x49, 0x89, 0x44, 0x24, 0x10, 0x0F, 0x10, 0x06, 0x41,
								  0x0F, 0x11, 0x04, 0x24, 0x5B, 0x41, 0x5C, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3, 0x4C};
			std::vector<uint8_t> expected_v(expected, expected + sizeof(expected));
			uint64_t searchOffset = 0;
			while (true)
			{
				uint64_t address = SearchRangeAddressInModule(pmap, hexPattern_v, searchOffset);
				if (address == 0)
					break;
				address += sizeof(hexPattern) - 1;
				printf("call address: %lx, RVA: 0x%lx\n", address, address - base);
				FuncPtr funcptr = reinterpret_cast<FuncPtr>(GetCallAddress(reinterpret_cast<uint8_t *>(address)));
				printf("funcptr: %p, RVA: 0x%lx\n", funcptr, reinterpret_cast<uint64_t>(funcptr) - base);
				// 检查是否为目标函数
				if (std::equal(expected_v.begin(), expected_v.end(), reinterpret_cast<uint8_t *>(funcptr)))
					return std::make_pair(address, funcptr);

				// 搜索到的非目标函数 进一步搜索
				searchOffset = address - pmap->start();
			}
		}
	} while ((pmap = pmap->next()) != nullptr);
#elif defined(_WIN_PLATFORM_)
	HMODULE wrapperModule = GetModuleHandleW(L"wrapper.node"); // 内存
	MODULEINFO modInfo;
	if (wrapperModule == NULL || !GetModuleInformation(GetCurrentProcess(), wrapperModule, &modInfo, sizeof(MODULEINFO)))
		return std::make_pair(0, nullptr);
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
	// printf("beforeOffect: %llx, RVA: 0x%llx\n", beforeOffect, beforeOffect - reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll));
	if (beforeOffect <= 0)
		return std::make_pair(0, nullptr);

	int64_t searchOffset = beforeOffect + sizeof(hexPattern_Before) - 1 - reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
	// 0x1CB0015;
	while (true)
	{
		uint64_t address = SearchRangeAddressInModule(wrapperModule, hexPattern_v, searchOffset, 0x1CF0015);
		if (address <= 0)
			break;
		address += sizeof(hexPattern) - 1;
		printf("address: %llx, RVA: 0x%llx\n", address, address - reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll));
		FuncPtr funcptr = reinterpret_cast<FuncPtr>(GetCallAddress(reinterpret_cast<uint8_t *>(address)));
		printf("funcptr: %p, RVA: 0x%llx\n", funcptr, reinterpret_cast<uint64_t>(funcptr) - reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll));
		if (std::equal(expected_v.begin(), expected_v.end(), reinterpret_cast<uint8_t *>(funcptr)))
			return std::make_pair(address, funcptr);

		// 获得的RVA在CALL前面 无法再次匹配 进一步搜索
		searchOffset = address - reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
	}
#endif
	return std::make_pair(0, nullptr);
}

namespace demo
{
	napi_value HookRkey(napi_env env, napi_callback_info args)
	{
		napi_value greeting;
		napi_status status;
		size_t argc = 1;
		napi_value argv[1] = {nullptr};
		char *QQversion = new char[1024];
		size_t str_size = 1024;
		napi_get_cb_info(env, args, &argc, argv, nullptr, nullptr);
		napi_get_value_string_utf8(env, argv[0], QQversion, str_size, &str_size);

		std::tie(callptr, orifuncptr) = searchRkeyByTable(QQversion);

		if (callptr == 0 || orifuncptr == nullptr)
		{
			printf("QQversion: %s not in table, try to search in memory\n", QQversion);
			try
			{
				std::tie(callptr, orifuncptr) = searchRkeyByMemory();
			}
			catch (...)
			{
				status = napi_create_string_utf8(env, "crash when search", NAPI_AUTO_LENGTH, &greeting);
				delete[] QQversion;
				return greeting;
			}

			if (callptr == 0 || orifuncptr == nullptr)
			{
				status = napi_create_string_utf8(env, "error search", NAPI_AUTO_LENGTH, &greeting);
				delete[] QQversion;
				return greeting;
			}
		}

		if (!Hook(reinterpret_cast<uint8_t *>(callptr), (void *)recvRkey))
		{
			status = napi_create_string_utf8(env, "error hook", NAPI_AUTO_LENGTH, &greeting);
			delete[] QQversion;
			return greeting;
		}
		status = napi_create_string_utf8(env, std::to_string(callptr).c_str(), NAPI_AUTO_LENGTH, &greeting);
		delete[] QQversion;
		return greeting;
	}
	napi_value GetRkey(napi_env env, napi_callback_info args)
	{
		napi_value greeting;
		napi_status status;
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