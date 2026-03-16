# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

macro(add_cdf_test_if NAME BUILD_TEST)
  if(BUILD_TEST)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE CDF::cdf Dependency::gtest
                                          Dependency::openssl)
    target_include_directories(${NAME} PRIVATE ${CMAKE_DEPENDENCY_INCLUDEDIR})
    add_test(NAME ${NAME} COMMAND ${NAME})
    set_tests_properties(
      ${NAME}
      PROPERTIES ENVIRONMENT "CDF_OPENSSL_PATH=${CMAKE_DEPENDENCY_LIBDIR};\
LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH")
  endif()
endmacro()
