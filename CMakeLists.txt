cmake_minimum_required(VERSION 3.14.1)

project(cdf VERSION 1.0.0 LANGUAGES C CXX)

if(POLICY CMP0097)
  cmake_policy(SET CMP0097 NEW)
endif()
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(ProjectOptions)
include(ResolveModules)
cdf_declare_project_options()
cdf_validate_project_options()
cdf_resolve_modules(CDF_REQUESTED_MODULES CDF_AUTO_ENABLED_MODULES
                    CDF_EFFECTIVE_MODULES)

include(GNUInstallDirs)
set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_SKIP_RPATH TRUE)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE "${PROJECT_BINARY_DIR}")
endif()

set(DEPENDENCY_INSTALL_PREFIX_NAME deps)
set(CMAKE_DEPENDENCY_INSTALL_PREFIX
    "${CMAKE_BINARY_DIR}/${DEPENDENCY_INSTALL_PREFIX_NAME}")
set(CMAKE_DEPENDENCY_INCLUDEDIR
    "${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}")
set(CMAKE_DEPENDENCY_LIBDIR
    "${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
if(ENABLE_DOWNLOAD_DEPENDENCY)
  set(CMAKE_DEPENDENCY_SRCDIR "${CMAKE_DEPENDENCY_INSTALL_PREFIX}/src")
else()
  set(CMAKE_DEPENDENCY_SRCDIR "${DOWNLOAD_DIR}")
endif()

include(FetchContent)
include(ExternalProject)
include(ImportLib)
set(FETCHCONTENT_BASE_DIR "${CMAKE_DEPENDENCY_INSTALL_PREFIX}/src")

include(CompilerWarnings)
include(SecurityHardening)
include(Sanitizers)
include(SetupFuzz)
cdf_configure_compiler_warnings()
cdf_configure_security_hardening()
cdf_configure_sanitizers()
cdf_configure_fuzzing()

if(BUILD_COVERAGE)
  include(SetupCoverage)
  cdf_configure_coverage()
endif()

function(cdf_apply_project_options target)
  target_link_libraries(${target} PRIVATE cdf_warnings cdf_hardening)
  set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  get_target_property(target_type ${target} TYPE)
  if(target_type STREQUAL "EXECUTABLE" AND
     CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(${target} PRIVATE -rdynamic)
  endif()
  if(BUILD_ASAN)
    target_link_libraries(${target} PRIVATE cdf_asan_options)
  endif()
  if(BUILD_FUZZ)
    target_link_libraries(${target} PRIVATE cdf_fuzz_options)
  endif()
  if(BUILD_COVERAGE AND TARGET cdf_coverage_options)
    target_link_libraries(${target} PRIVATE cdf_coverage_options)
  endif()
endfunction()

function(cdf_install_headers destination)
  install(FILES ${ARGN}
    DESTINATION "${destination}"
    PERMISSIONS OWNER_READ GROUP_READ)
endfunction()

include(Dependencies)
cdf_configure_dependencies()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${PROJECT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${PROJECT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${PROJECT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}")

message(STATUS "==============================================================")
message(STATUS "CDF build configuration")
message(STATUS "==============================================================")
message(STATUS "CMake version                 : ${CMAKE_VERSION}")
if(CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Build configurations          : ${CMAKE_CONFIGURATION_TYPES}")
else()
  message(STATUS "Build type                    : ${CMAKE_BUILD_TYPE}")
endif()
message(STATUS "Compiler                      : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Install prefix                : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Dependency source directory   : ${CMAKE_DEPENDENCY_SRCDIR}")
message(STATUS "Download dependencies         : ${ENABLE_DOWNLOAD_DEPENDENCY}")
message(STATUS "Build tests                   : ${BUILD_TEST}")
message(STATUS "Build coverage                : ${BUILD_COVERAGE}")
message(STATUS "Build ASan                    : ${BUILD_ASAN}")
message(STATUS "Build fuzz                    : ${BUILD_FUZZ}")
message(STATUS "Build shared library          : ${ENABLE_SHARED}")
message(STATUS "Requested modules             : ${CDF_REQUESTED_MODULES}")
message(STATUS "Automatically enabled modules : ${CDF_AUTO_ENABLED_MODULES}")
message(STATUS "Effective modules             : ${CDF_EFFECTIVE_MODULES}")
message(STATUS "==============================================================")

add_subdirectory(src/cdf)

if(BUILD_TEST)
  include(CTest)
  enable_testing()
  add_subdirectory(test)
endif()

include(Packaging)
cdf_configure_packaging()
