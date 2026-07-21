include_guard(GLOBAL)

function(cdf_configure_fuzzing)
  add_library(cdf_fuzz_options INTERFACE)
  if(BUILD_FUZZ)
    add_library(cdf_fuzz_runtime STATIC
      "${PROJECT_SOURCE_DIR}/src/cdf/fuzz/fuzz_runtime.cpp")
    set_target_properties(cdf_fuzz_runtime PROPERTIES
      POSITION_INDEPENDENT_CODE ON)

    target_compile_options(cdf_fuzz_options INTERFACE
      -fsanitize=address
      -fsanitize-coverage=trace-pc,trace-cmp
      -fno-omit-frame-pointer)
    target_link_options(cdf_fuzz_options INTERFACE
      -fsanitize=address
      -fsanitize-coverage=trace-pc,trace-cmp)
    target_link_libraries(cdf_fuzz_options INTERFACE cdf_fuzz_runtime)
  endif()
endfunction()
