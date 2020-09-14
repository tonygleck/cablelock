#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.5.0)

function(add_sample_directory whatIsBuilding)
    add_subdirectory(${whatIsBuilding})

    set_target_properties(${whatIsBuilding} PROPERTIES FOLDER "Samples")
endfunction()

add_subdirectory(cablelock_des_sample)
add_subdirectory(cablelock_cert_sample)
