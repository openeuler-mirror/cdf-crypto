if(NOT DEFINED SOURCE_DIR OR NOT DEFINED DESTINATION_DIR)
  message(FATAL_ERROR "SOURCE_DIR and DESTINATION_DIR are required")
endif()

find_program(GIT_EXECUTABLE git)
if(NOT GIT_EXECUTABLE)
  message(FATAL_ERROR "git is required to prepare offline dependency sources")
endif()

execute_process(
  COMMAND "${GIT_EXECUTABLE}" -C "${SOURCE_DIR}" rev-parse
          --is-inside-work-tree
  RESULT_VARIABLE git_worktree_result
  OUTPUT_QUIET
  ERROR_QUIET)
if(NOT git_worktree_result EQUAL 0)
  message(FATAL_ERROR
    "Offline dependency source is not a Git worktree: ${SOURCE_DIR}")
endif()

get_filename_component(destination_parent "${DESTINATION_DIR}" DIRECTORY)
get_filename_component(destination_name "${DESTINATION_DIR}" NAME)
set(source_archive "${destination_parent}/${destination_name}-source.tar")

file(REMOVE_RECURSE "${DESTINATION_DIR}")
file(MAKE_DIRECTORY "${DESTINATION_DIR}")
execute_process(
  COMMAND "${GIT_EXECUTABLE}" -C "${SOURCE_DIR}" archive --format=tar
          "--output=${source_archive}" HEAD
  RESULT_VARIABLE archive_result)
if(NOT archive_result EQUAL 0)
  message(FATAL_ERROR "Failed to archive dependency source: ${SOURCE_DIR}")
endif()

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E tar xvf "${source_archive}"
  WORKING_DIRECTORY "${DESTINATION_DIR}"
  RESULT_VARIABLE extract_result
  OUTPUT_QUIET)
file(REMOVE "${source_archive}")
if(NOT extract_result EQUAL 0)
  message(FATAL_ERROR "Failed to extract dependency source into: ${DESTINATION_DIR}")
endif()
