cmake_minimum_required(VERSION 3.20)
project(dmcps VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json 3.11 REQUIRED)

include(FetchContent)
# TLS terminates at the reverse proxy; keep the embedded HTTP server minimal.
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
FetchContent_Declare(cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.67.0
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(cpp_httplib)

add_executable(dmcps src/main.cpp)
target_include_directories(dmcps PRIVATE include)
target_link_libraries(dmcps PRIVATE httplib::httplib nlohmann_json::nlohmann_json CURL::libcurl Threads::Threads)
target_compile_options(dmcps PRIVATE -Wall -Wextra -Wpedantic)

include(CTest)
if(BUILD_TESTING)
    add_executable(dmcps-security-tests tests/security_tests.cpp)
    target_include_directories(dmcps-security-tests PRIVATE include)
    target_compile_options(dmcps-security-tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME security-path-boundaries COMMAND dmcps-security-tests)
endif()

install(TARGETS dmcps RUNTIME DESTINATION bin)
