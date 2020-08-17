#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.3.0)

set(cablelock_sample_files
    cablelock_des_sample.c
)

add_executable(cablelock_des_sample ${cablelock_sample_files})

target_link_libraries(cablelock_des_sample cablelock) # lib-util-c)
