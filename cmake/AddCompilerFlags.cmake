
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

include(CheckCXXCompilerFlag)

# For easier adding of CXX compiler flags
function(add_compiler_flags flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS
                    "${CMAKE_CXX_FLAGS} ${flag}"
                    PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

# For easier adding of C compiler flags
function(add_c_compiler_flags flag)
    string(FIND "${CMAKE_C_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding C compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_C_FLAGS
                    "${CMAKE_C_FLAGS} ${flag}"
                    PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

function(add_release_compiler_flags flag)
    string(FIND "${CMAKE_CXX_FLAGS_RELEASE}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS_RELEASE
                    "${CMAKE_CXX_FLAGS_RELEASE} ${flag}"
                    PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

function(add_debug_compiler_flags flag)
    string(FIND "${CMAKE_CXX_FLAGS_DEBUG}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS_DEBUG
                    "${CMAKE_CXX_FLAGS_DEBUG} ${flag}"
                    PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()