#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.2.0)
project(cablelock)

option(cablelock_ut "Include unittest in build" OFF)
option(cablelock_samples "Include samples in build" ON)

# Enable or disable test coverage
if (CMAKE_BUILD_TYPE MATCHES "Debug" AND NOT WIN32)
    set(DEBUG_CONFIG ON)
    set(ENABLE_COVERAGE ON)
else()
    set(ENABLE_COVERAGE OFF)
    set(DEBUG_CONFIG OFF)
endif()

include("${PROJECT_SOURCE_DIR}/cmake_configs/proj_config.cmake")

# Setup dependencies
if (NOT TARGET azure_macro_utils_c)
    add_subdirectory(${PROJECT_SOURCE_DIR}/deps/azure-macro-utils-c)
    include_directories(${MACRO_UTILS_INC_FOLDER})
endif()
if (NOT TARGET umock_c)
    add_subdirectory(${PROJECT_SOURCE_DIR}/deps/umock-c)
    include_directories(${UMOCK_C_INC_FOLDER})
endif()
if (NOT TARGET lib-util-c)
    add_subdirectory(${PROJECT_SOURCE_DIR}/deps/lib-util-c)
    include_directories(${PROJECT_SOURCE_DIR}/deps/lib-util-c/inc/)
endif()

include_directories(${CMAKE_CURRENT_LIST_DIR}/inc)

set(cablelock_h_files
    ${PROJECT_SOURCE_DIR}/inc/cablelock/crypto_ciphers.h
)

set(cablelock_c_files
    ${PROJECT_SOURCE_DIR}/src/crypto_aes.c
    ${PROJECT_SOURCE_DIR}/src/crypto_des.c
)

add_library(cablelock ${cablelock_c_files} ${cablelock_h_files})
target_link_libraries(cablelock lib-util-c)

crypto_addCompileSettings(cablelock)
#addCompileSettings(cablelock)
compileTargetAsC99(cablelock)

if (${cablelock_samples})
    add_subdirectory(samples)
endif()

if (${cablelock_ut})
    include("${CMAKE_CURRENT_LIST_DIR}/cmake_configs/proj_testing.cmake")
    enable_coverage_testing()

    if ((NOT TARGET ctest) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/azure-ctest/CMakeLists.txt))
        add_subdirectory(${PROJECT_SOURCE_DIR}/deps/azure-ctest)
    endif()
    include_directories(${CTEST_INC_FOLDER})

    enable_testing()
    include (CTest)

    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()