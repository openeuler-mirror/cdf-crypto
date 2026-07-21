cmake_minimum_required(VERSION 3.14.1)
project(cdf_coverage_scope_test LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CDF_SOURCE_DIR}/cmake")
include(SetupCoverage)
cdf_configure_coverage()

if(NOT TARGET cdf_coverage_options)
  message(FATAL_ERROR "cdf_coverage_options target was not created")
endif()

get_target_property(compile_options cdf_coverage_options
                    INTERFACE_COMPILE_OPTIONS)
get_target_property(link_options cdf_coverage_options
                    INTERFACE_LINK_OPTIONS)
if(NOT "--coverage" IN_LIST compile_options)
  message(FATAL_ERROR "coverage compile option is missing: ${compile_options}")
endif()
if(NOT "--coverage" IN_LIST link_options)
  message(FATAL_ERROR "coverage link option is missing: ${link_options}")
endif()
