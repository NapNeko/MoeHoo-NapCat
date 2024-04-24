cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)
cmake_policy(SET CMP0042 NEW)

project (MoeHoo)
# 指定utf8

#
#if(MSVC)
#	add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
#	add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
#endif()

# 平台宏定义
if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(_WIN_PLATFORM_ true)
    add_definitions(-D _WIN_PLATFORM_)
endif()

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(_LINUX_PLATFORM_ true)
    add_definitions(-D _LINUX_PLATFORM_)
endif()

# 设置NAPI版本
add_definitions(-DNAPI_VERSION=7)

# 设置CPP标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 引入NAPI支持
include_directories(${CMAKE_JS_INC})

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/MoeHoo/include/")

include_directories("${CMAKE_SOURCE_DIR}/node_modules/node-api-headers/include")
file(GLOB SOURCE_FILES "./MoeHoo/src/*.cpp")

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})

if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
  execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()