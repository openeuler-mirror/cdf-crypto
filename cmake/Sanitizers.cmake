include_guard(GLOBAL)

function(cdf_configure_sanitizers)
  add_library(cdf_asan_options INTERFACE)
  if(BUILD_ASAN)
    target_compile_options(cdf_asan_options INTERFACE
      -fsanitize=address
      -fno-omit-frame-pointer)
    target_link_options(cdf_asan_options INTERFACE -fsanitize=address)
  endif()
endfunction()
