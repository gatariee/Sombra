cmake_minimum_required(VERSION 3.27)
project(demon)

set(PROJECT_NAME demon)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_FLAGS "-Wl,--pic-executable,-e,WinMain -Wl,-Bdynamic -w -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -nostdlib")
include_directories(
        include
)

set(SRC
        Main.cc

        entry/Exe.cc

        core/Print.cc
        core/Initialize.cc
)

add_compile_definitions(
        DEBUG
)

add_executable(${PROJECT_NAME} ${SRC})
