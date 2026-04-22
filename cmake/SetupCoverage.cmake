find_program(GCOV_PATH gcov)
find_program(LCOV_PATH lcov)
find_program(GENHTML_PATH genhtml)
find_program(GCOVR_PATH gcovr)
find_program(Python3 python3)

function(setup_coverage)
  if(NOT GCOV_PATH)
    message(FATAL_ERROR "gcov not found! Aborting...")
  endif()

  set(COVERAGE_COMPILER_FLAGS "-g --coverage")
  set(CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} ${COVERAGE_COMPILER_FLAGS}"
      PARENT_SCOPE)
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} ${COVERAGE_COMPILER_FLAGS}"
      PARENT_SCOPE)
  set(COVERAGE_DIR ${CMAKE_BINARY_DIR}/coverage)
  message(
    STATUS "Appending code coverage compiler flags: ${COVERAGE_COMPILER_FLAGS}")

  link_libraries(gcov)

  execute_process(COMMAND mkdir -p ${CMAKE_BINARY_DIR}/coverage
                  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

  if(LCOV_PATH)
    message(STATUS "locv found in ${LCOV_PATH}.")
    set(HTML_PATH ${CMAKE_BINARY_DIR}/coverage/index.html)
    set(LCOV_CONFIG_FILE "${COVERAGE_DIR}/lcov.conf")
    add_custom_target(
      coverage
      COMMAND echo "lcov_branch_coverage = 1" > ${LCOV_CONFIG_FILE} # 启用分支覆盖率
      COMMAND echo "lcov_excl_br_line = \"LCOV_EXCL_BR_LINE|RACK_LOG_*\"" >>
              ${LCOV_CONFIG_FILE} # 排除 RACK 开头的宏日志计算到分支覆盖率
      COMMAND
        ${LCOV_PATH} --include '${PROJECT_SOURCE_DIR}/src/*' --config-file ${LCOV_CONFIG_FILE} -d ${CMAKE_BINARY_DIR}/src -c -o
        ${COVERAGE_DIR}/coverage.info --gcov-tool=${GCOV_PATH} # 获取所有覆盖率信息
      #   ${Python3} cmake/scripts/filter_tool.py --input
      #   ${COVERAGE_DIR}/coverage.info --output ${COVERAGE_DIR}/filter.info
      #   --root ${CMAKE_BINARY_DIR}/src
      COMMAND
        ${GENHTML_PATH} --config-file ${LCOV_CONFIG_FILE} -o
        ${CMAKE_BINARY_DIR}/coverage --legend ${COVERAGE_DIR}/coverage.info
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    if(POWERSHELL_PATH)
      message(STATUS "powershell found in ${POWERSHELL_PATH}")
      add_custom_command(
        TARGET coverage
        POST_BUILD
        COMMAND ${POWERSHELL_PATH} /c start build/coverage/index.html;
        COMMENT "Open ${HTML_PATH} in your browser to view the coverage report."
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    else()
      add_custom_command(
        TARGET coverage
        POST_BUILD
        COMMAND ;
        COMMENT "Open ${HTML_PATH} in your browser to view the coverage report."
      )
    endif()
  elseif(GCOVR_PATH)
    message(STATUS "gcovr found in ${GCOVR_PATH}.")
    set(HTML_PATH ${CMAKE_BINARY_DIR}/coverage/total.html)
    add_custom_target(
      coverage
      COMMAND ${GCOVR_PATH} -f src --gcov-exclude '.+log.+' --html-details
              ${HTML_PATH}
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    if(POWERSHELL_PATH)
      message(STATUS "powershell found in ${POWERSHELL_PATH}")
      add_custom_command(
        TARGET coverage
        POST_BUILD
        COMMAND ${POWERSHELL_PATH} /c start build/coverage/total.html;
        COMMENT "Open ${HTML_PATH} in your browser to view the coverage report."
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    else()
      add_custom_command(
        TARGET coverage
        POST_BUILD
        COMMAND ;
        COMMENT "Open ${HTML_PATH} in your browser to view the coverage report."
      )
    endif()
  else()
    message(AUTHOR_WARNING "gcovr not found! replaced by gcov.")
    add_custom_target(
      coverage
      COMMAND rm -rf *.gcov
      COMMAND find ${CMAKE_BINARY_DIR}/src -name '*.gcda' -exec gcov -pb {} +
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/coverage)
  endif()
endfunction()
