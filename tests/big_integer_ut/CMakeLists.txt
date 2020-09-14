#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.2.0)

set(theseTestsName big_integer_ut)

set(${theseTestsName}_test_files
    ${theseTestsName}.c
)

set(${theseTestsName}_c_files
    ../../src/big_integer.c
)

set(${theseTestsName}_h_files
)

build_test_project(${theseTestsName} "tests/cablelock_tests")
