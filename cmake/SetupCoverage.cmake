include_guard(GLOBAL)

function(cdf_configure_coverage)
  add_library(cdf_coverage_options INTERFACE)
  target_compile_options(cdf_coverage_options INTERFACE -g --coverage
                                                     -fprofile-update=atomic)
  target_link_options(cdf_coverage_options INTERFACE --coverage)
  target_compile_definitions(cdf_coverage_options INTERFACE LCOV_IGNORE)

  find_program(GCOV_PATH gcov)
  find_program(LCOV_PATH lcov)
  find_program(GENHTML_PATH genhtml)

  if(NOT GCOV_PATH)
    message(FATAL_ERROR "gcov is required when BUILD_COVERAGE=ON")
  endif()
  if(NOT LCOV_PATH)
    message(FATAL_ERROR "lcov is required when BUILD_COVERAGE=ON")
  endif()
  if(NOT GENHTML_PATH)
    message(FATAL_ERROR "genhtml is required when BUILD_COVERAGE=ON")
  endif()

  execute_process(
    COMMAND "${LCOV_PATH}" --help
    OUTPUT_VARIABLE lcov_help_output
    ERROR_VARIABLE lcov_help_error
    RESULT_VARIABLE lcov_help_result)
  set(lcov_help_text "${lcov_help_output}\n${lcov_help_error}")
  execute_process(
    COMMAND "${LCOV_PATH}" --version
    OUTPUT_VARIABLE lcov_version_output
    ERROR_VARIABLE lcov_version_error
    RESULT_VARIABLE lcov_version_result)
  set(lcov_version_text "${lcov_version_output}\n${lcov_version_error}")
  if(lcov_help_result EQUAL 0
     AND lcov_help_text MATCHES "--\\(no-\\)branch-coverage|--branch-coverage")
    set(lcov_branch_coverage_arguments --branch-coverage)
  else()
    set(lcov_branch_coverage_arguments --rc lcov_branch_coverage=1)
  endif()
  if(lcov_version_result EQUAL 0 AND lcov_version_text MATCHES "LCOV version 2")
    set(lcov_capture_ignore_arguments --ignore-errors mismatch)
    set(lcov_remove_ignore_arguments --ignore-errors unused)
  else()
    set(lcov_capture_ignore_arguments)
    set(lcov_remove_ignore_arguments)
  endif()

  execute_process(
    COMMAND "${GENHTML_PATH}" --help
    OUTPUT_VARIABLE genhtml_help_output
    ERROR_VARIABLE genhtml_help_error
    RESULT_VARIABLE genhtml_help_result)
  set(genhtml_help_text "${genhtml_help_output}\n${genhtml_help_error}")
  if(genhtml_help_result EQUAL 0
     AND genhtml_help_text MATCHES "--\\(no-\\)branch-coverage|--branch-coverage")
    set(genhtml_branch_coverage_arguments --branch-coverage)
  else()
    set(genhtml_branch_coverage_arguments --rc genhtml_branch_coverage=1)
  endif()

  set(report_directory "${CMAKE_BINARY_DIR}/report")
  set(html_report "${report_directory}/index.html")
  set(raw_coverage_info "${report_directory}/coverage.raw.info")
  set(filtered_coverage_info "${report_directory}/coverage.info")

  add_custom_target(
    coverage
    COMMAND ${CMAKE_COMMAND} -E make_directory "${report_directory}"
    COMMAND ${LCOV_PATH}
            --capture
            --directory "${CMAKE_BINARY_DIR}"
            --base-directory "${PROJECT_SOURCE_DIR}"
            --gcov-tool "${GCOV_PATH}"
            ${lcov_branch_coverage_arguments}
            ${lcov_capture_ignore_arguments}
            --output-file "${raw_coverage_info}"
    COMMAND ${LCOV_PATH}
            --remove "${raw_coverage_info}"
            "/usr/*"
            "${PROJECT_SOURCE_DIR}/external/*"
            "${PROJECT_SOURCE_DIR}/test/*"
            "${CMAKE_BINARY_DIR}/*"
            ${lcov_branch_coverage_arguments}
            ${lcov_remove_ignore_arguments}
            --output-file "${filtered_coverage_info}"
    COMMAND ${GENHTML_PATH}
            "${filtered_coverage_info}"
            --output-directory "${report_directory}"
            ${genhtml_branch_coverage_arguments}
            --legend
            --title "cdf-crypto coverage"
            --rc genhtml_hi_limit=90
            --rc genhtml_med_limit=70
            --rc genhtml_line_hi_limit=90
            --rc genhtml_line_med_limit=70
            --rc genhtml_branch_hi_limit=60
            --rc genhtml_branch_med_limit=50
    COMMAND ${CMAKE_COMMAND} -E touch "${html_report}"
    VERBATIM
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    COMMENT "Generate coverage reports in ${report_directory}")
endfunction()
