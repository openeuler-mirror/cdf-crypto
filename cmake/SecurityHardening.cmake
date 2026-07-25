include_guard(GLOBAL)

function(cdf_configure_security_hardening)
  add_library(cdf_hardening INTERFACE)

  foreach(language C CXX)
    foreach(flag -fno-common -pipe -fno-strict-aliasing)
      cdf_add_supported_compile_option(cdf_hardening ${language} "${flag}")
    endforeach()
    foreach(flag -O2 -fstack-protector-strong -ftrapv)
      string(MAKE_C_IDENTIFIER "${language}_${flag}" flag_identifier)
      set(result_variable "CDF_SUPPORTS_RELEASE_${flag_identifier}")
      if(language STREQUAL "C")
        check_c_compiler_flag("${flag}" ${result_variable})
      else()
        check_cxx_compiler_flag("${flag}" ${result_variable})
      endif()
      if(${result_variable})
        target_compile_options(cdf_hardening INTERFACE
          "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:${language}>>:${flag}>")
      endif()
    endforeach()
  endforeach()

  target_compile_definitions(cdf_hardening INTERFACE
    "$<$<CONFIG:Release>:_FORTIFY_SOURCE=2>")

  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(cdf_hardening INTERFACE
      -Wl,-Bsymbolic
      -Wl,--no-undefined
      "$<$<CONFIG:Release>:-Wl,-z,relro,-z,now>"
      "$<$<CONFIG:Release>:-Wl,-z,noexecstack>"
      "$<$<CONFIG:Release>:-s>")
  endif()
endfunction()
