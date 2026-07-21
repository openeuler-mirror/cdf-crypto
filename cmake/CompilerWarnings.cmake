include_guard(GLOBAL)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

function(cdf_add_supported_compile_option target language flag)
  string(MAKE_C_IDENTIFIER "${language}_${flag}" flag_identifier)
  set(result_variable "CDF_SUPPORTS_${flag_identifier}")

  if(language STREQUAL "C")
    check_c_compiler_flag("${flag}" ${result_variable})
  elseif(language STREQUAL "CXX")
    check_cxx_compiler_flag("${flag}" ${result_variable})
  else()
    message(FATAL_ERROR "Unsupported compile language '${language}'")
  endif()

  if(${result_variable})
    target_compile_options(${target} INTERFACE
      "$<$<COMPILE_LANGUAGE:${language}>:${flag}>")
  endif()
endfunction()

function(cdf_configure_compiler_warnings)
  add_library(cdf_warnings INTERFACE)

  set(cxx_warnings
      -Wall
      -Wextra
      -Werror
      -Winvalid-pch
      -fms-extensions
      -Wunused-variable
      -Wunused-value
      -Wcast-align
      -Wcast-qual
      -Wwrite-strings
      -Wdate-time
      -Wunused
      -freg-struct-return
      -Wdelete-non-virtual-dtor
      -fstrong-eval-order
      -Wtrampolines
      -Wformat=2
      -Wfloat-equal
      -Wshadow
      -Wswitch-default
      -Wundef)
  foreach(flag IN LISTS cxx_warnings)
    cdf_add_supported_compile_option(cdf_warnings CXX "${flag}")
  endforeach()

  set(c_warnings
      -Wall
      -Wextra
      -Werror
      -Wdate-time
      -Wstrict-prototypes
      -Wunused
      -Wfloat-equal
      -Wvla
      -freg-struct-return
      -Wshadow
      -Wcast-align
      -Wtrampolines
      -Wstack-usage=8192)
  foreach(flag IN LISTS c_warnings)
    cdf_add_supported_compile_option(cdf_warnings C "${flag}")
  endforeach()
endfunction()
