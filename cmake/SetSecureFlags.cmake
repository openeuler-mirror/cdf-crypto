# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

include(CheckCXXCompilerFlag)
include(CheckCompilerFlag)
include(CheckLinkerFlag)

# For easier adding of CXX compiler flags
function(add_compiler_flags flag)
  # NOTE it's necessary to have "${flag} " the tailing space
  string(FIND "${CMAKE_CXX_FLAGS}" "${flag} " flag_already_set)
  if(flag_already_set EQUAL -1)
    message(STATUS "Adding CXX compiler flag: ${flag} ...")
    check_cxx_compiler_flag("${flag}" flag_supported)
    if(flag_supported)
      set(CMAKE_CXX_FLAGS
          "${CMAKE_CXX_FLAGS} ${flag}"
          PARENT_SCOPE)
    endif()
    unset(flag_supported CACHE)
  else()
    message(STATUS "Already set compiler flag: ${flag} ...")
  endif()
endfunction()

# For easier adding of C compiler flags
function(add_c_compiler_flags flag)
  string(FIND "${CMAKE_C_FLAGS}" "${flag} " flag_already_set)
  if(flag_already_set EQUAL -1)
    message(STATUS "Adding C compiler flag: ${flag} ...")
    check_compiler_flag(C "${flag}" flag_supported)
    if(flag_supported)
      set(CMAKE_C_FLAGS
          "${CMAKE_C_FLAGS} ${flag}"
          PARENT_SCOPE)
    endif()
    unset(flag_supported CACHE)
  else()
    message(STATUS "Already set C compiler flag: ${flag} ...")
  endif()
endfunction()

# NOTE LINK_OPTIONS holds a semicolon-separated list of options
# see: https://cmake.org/cmake/help/latest/prop_dir/LINK_OPTIONS.html
function(add_linker_flags flag)
  get_property(
    cdf_link_options
    DIRECTORY
    PROPERTY LINK_OPTIONS)
  string(FIND "${cdf_link_options}" "${flag};" flag_already_set)
  if(flag_already_set EQUAL -1)
    message(STATUS "Adding linker flag: ${flag} ...")
    check_linker_flag(CXX "${flag}" flag_supported)
    if(flag_supported)
      add_link_options(${flag})
    endif()
    unset(flag_supported CACHE)
  else()
    message(STATUS "Already set linker flag: ${flag} ...")
  endif()
endfunction()

macro(set_secure_flags)
  # do not add run time path information
  set(CMAKE_SKIP_RPATH TRUE)

  # common compiler flags (good-to-have)
  add_compiler_flags(-Wall)
  add_compiler_flags(-Wextra)
  add_compiler_flags(-Werror)
  add_compiler_flags(-fno-common)
  add_compiler_flags(-pipe)
  add_compiler_flags(-Winvalid-pch)
  add_compiler_flags(-fms-extensions)
  add_compiler_flags(-Wunused-variable)
  add_compiler_flags(-Wunused-value)
  add_compiler_flags(-Wcast-align)
  add_compiler_flags(-Wcast-qual)
  add_compiler_flags(-Wwrite-strings)
  add_compiler_flags(-Wdate-time)
  add_compiler_flags(-fno-strict-aliasing)
  add_compiler_flags(-Wstrict-prototypes)
  add_compiler_flags(-Wunused)
  add_compiler_flags(-freg-struct-return)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wdelete-non-virtual-dtor>)
  add_compiler_flags(-fstrong-eval-order)
  add_compiler_flags(-Wtrampolines)
  add_compiler_flags(-Woverloaded-virtua)

  # common linker flags (good-to-have)
  add_linker_flags(-Wl,-Bsymbolic)
  add_linker_flags(-rdynamic)
  add_linker_flags(-Wl,--no-undefined)

  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    # Build position independent code, even for static lib
    set(CMAKE_POSITION_INDEPENDENT_CODE On)

    # security-related compiler flags (must-have)
    add_compiler_flags(-fstack-protector-strong) # stack protection
    add_compiler_flags(-fPIC) # PIC
    add_compiler_flags(-fPIE) # PIE
    add_compiler_flags(-D_FORTIFY_SOURCE=2) # fs
    add_compiler_flags(-O2) # optimize level
    add_compiler_flags(-ftrapv) # ftrapv
    # add_compiler_flags(-s) # strip
    # add_compiler_flags(-Wl,-z,relro,-z,now) # bind now

    # security-related linker flags (must-have)
    add_linker_flags(-pie) # pie
    add_linker_flags(-s) # strip
    add_linker_flags(-Wl,-z,relro,-z,now) # bind now
    add_linker_flags(-Wl,-z,noexecstack) # nx
  elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compiler_flags(-g)
  endif()

  if(BUILD_ASAN)
    set(_saved_CRL ${CMAKE_REQUIRED_LIBRARIES})
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address;asan")
    add_compiler_flags(-fsanitize=address)
    add_compiler_flags(-fsanitize=leak)
    add_compiler_flags(-fsanitize=undefined)
    add_compiler_flags(-fsanitize=pointer-compare)
    add_compiler_flags(-fsanitize=pointer-subtract)

    add_linker_flags(-fno-pie)
    add_linker_flags(-fsanitize=address)
    add_linker_flags(-fsanitize=pointer-subtract)
    add_linker_flags(-fsanitize=pointer-compare)
    add_linker_flags(-fsanitize=undefined)
    add_linker_flags(-fsanitize=leak)
    set(CMAKE_REQUIRED_LIBRARIES ${_saved_CRL})
  endif()
endmacro()
