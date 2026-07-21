cmake_minimum_required(VERSION 3.14.1)

project(cdf_rand_consumer LANGUAGES CXX)

if(NOT CDF_PREFIX)
  message(FATAL_ERROR "CDF_PREFIX is required")
endif()

find_library(CDF_SHARED_LIBRARY
  NAMES cdf_shared
  PATHS "${CDF_PREFIX}"
  PATH_SUFFIXES lib lib64
  NO_DEFAULT_PATH)
if(NOT CDF_SHARED_LIBRARY)
  message(FATAL_ERROR "cdf_shared was not found below ${CDF_PREFIX}")
endif()

add_executable(cdf_rand_consumer main.cpp)
target_compile_features(cdf_rand_consumer PRIVATE cxx_std_17)
target_include_directories(cdf_rand_consumer PRIVATE "${CDF_PREFIX}/include")
target_link_libraries(cdf_rand_consumer PRIVATE "${CDF_SHARED_LIBRARY}")
