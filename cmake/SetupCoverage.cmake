include_guard(GLOBAL)

function(cdf_configure_coverage)
  add_library(cdf_coverage_options INTERFACE)
  target_compile_options(cdf_coverage_options INTERFACE -g --coverage)
  target_link_options(cdf_coverage_options INTERFACE --coverage)
  target_compile_definitions(cdf_coverage_options INTERFACE LCOV_IGNORE)

  find_program(GCOV_PATH gcov)
  find_program(GCOVR_PATH gcovr)

  if(NOT GCOV_PATH)
    message(FATAL_ERROR "gcov is required when BUILD_COVERAGE=ON")
  endif()
  if(NOT GCOVR_PATH)
    message(FATAL_ERROR "gcovr is required when BUILD_COVERAGE=ON")
  endif()

  set(report_directory "${CMAKE_BINARY_DIR}/report")
  set(html_report "${report_directory}/total.html")
  set(common_gcovr_arguments
      "${CMAKE_BINARY_DIR}"
      --root "${PROJECT_SOURCE_DIR}"
      --object-directory "${CMAKE_BINARY_DIR}"
      --filter "${PROJECT_SOURCE_DIR}/src"
      --gcov-executable "${GCOV_PATH}"
      --gcov-exclude ".+log.+"
      --gcov-ignore-parse-errors negative_hits.warn_once_per_file)

  add_custom_target(
    coverage
    COMMAND ${CMAKE_COMMAND} -E make_directory "${report_directory}"
    COMMAND ${GCOVR_PATH} ${common_gcovr_arguments}
            --html-medium-threshold-line 70
            --html-high-threshold-line 90
            --html-medium-threshold-branch 40
            --html-high-threshold-branch 60
            --html-details "${html_report}"
    COMMAND ${GCOVR_PATH} ${common_gcovr_arguments}
            --xml-pretty --output "${report_directory}/coverage.xml"
    COMMAND ${GCOVR_PATH} ${common_gcovr_arguments}
            --txt --output "${report_directory}/coverage.txt"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    COMMENT "Generate coverage reports in ${report_directory}")
endfunction()
