cmake_minimum_required(VERSION 3.3)
project(AesEncryptTest)

set(TARGET_NAME AesEncryptTest)

include_directories("/usr/local/Cellar/openssl/1.0.2d_1/include")
link_directories ("/usr/local/Cellar/openssl/1.0.2d_1/lib")
set (LINK_LIBS libssl.a libcrypto.a)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES ../main.cpp)
add_executable(${TARGET_NAME} ${SOURCE_FILES})
target_link_libraries(${TARGET_NAME} ${LINK_LIBS})