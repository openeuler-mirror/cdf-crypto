include_guard(GLOBAL)

function(cdf_declare_project_options)
  option(BUILD_TEST "Build CDF tests" ON)
  option(BUILD_COVERAGE "Enable CDF coverage instrumentation" OFF)
  option(BUILD_FUZZ "Build fuzz-instrumented CDF targets" OFF)
  option(BUILD_ASAN "Enable AddressSanitizer for CDF targets" OFF)
  option(ENABLE_DOWNLOAD_DEPENDENCY "Download missing dependencies" OFF)
  option(ENABLE_SHARED "Build the CDF shared library" ON)
  option(ENABLE_BLAKE3 "Enable the optional built-in BLAKE3 backend" OFF)

  option(ENABLE_ALL_MODULES "Build all CDF modules" OFF)
  option(ENABLE_MODULE_AUTHENTICATION "Build the authentication module" OFF)
  option(ENABLE_MODULE_AUTHORIZATION "Build the authorization module" OFF)
  option(ENABLE_MODULE_CRYPTION "Build the cryption module" OFF)
  option(ENABLE_MODULE_CLI_TOOL "Build the CLI tool" OFF)
  option(ENABLE_MODULE_KEY_MANAGEMENT "Build the key management module" OFF)
  option(ENABLE_MODULE_RAND "Build the rand module" OFF)
  option(ENABLE_MODULE_PSK_MANAGEMENT "Build the PSK management module" OFF)

  set(ENABLE_MODULES "" CACHE STRING
      "Semicolon-separated CDF modules, or ALL for every module")
  set(DOWNLOAD_DIR "${PROJECT_SOURCE_DIR}/external" CACHE PATH
      "Pre-provisioned dependency source directory")
  set(OPENSSL_SOURCE_ARCHIVE "" CACHE FILEPATH
      "Pre-provisioned OpenSSL source archive")
  set(LIBBOUNDSCHECK_SOURCE_ARCHIVE "" CACHE FILEPATH
      "Pre-provisioned libboundscheck source archive")
  set(RAPIDJSON_SOURCE_ARCHIVE "" CACHE FILEPATH
      "Pre-provisioned RapidJSON source archive")
  set(KRB5_SOURCE_ARCHIVE "" CACHE FILEPATH
      "Pre-provisioned Kerberos source archive")
  set(BLAKE3_SOURCE_ARCHIVE "" CACHE FILEPATH
      "Pre-provisioned BLAKE3 source archive")

  if(DEFINED DOWNLOAD_DEPENDENCY)
    message(DEPRECATION
      "DOWNLOAD_DEPENDENCY is deprecated; use ENABLE_DOWNLOAD_DEPENDENCY")
    set(ENABLE_DOWNLOAD_DEPENDENCY "${DOWNLOAD_DEPENDENCY}" CACHE BOOL
        "Download missing dependencies" FORCE)
  endif()
endfunction()

function(cdf_validate_project_options)
  set(dependency_source_archives
      OPENSSL_SOURCE_ARCHIVE
      LIBBOUNDSCHECK_SOURCE_ARCHIVE
      RAPIDJSON_SOURCE_ARCHIVE
      KRB5_SOURCE_ARCHIVE
      BLAKE3_SOURCE_ARCHIVE)
  foreach(archive_variable IN LISTS dependency_source_archives)
    if(ENABLE_DOWNLOAD_DEPENDENCY AND ${archive_variable})
      message(FATAL_ERROR
        "${archive_variable} cannot be used with ENABLE_DOWNLOAD_DEPENDENCY=ON")
    endif()
    if(${archive_variable} AND NOT EXISTS "${${archive_variable}}")
      message(FATAL_ERROR
        "${archive_variable} does not exist: ${${archive_variable}}")
    endif()
  endforeach()

  get_property(is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
  if(NOT is_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  endif()

  if(BUILD_COVERAGE AND NOT BUILD_TEST)
    message(STATUS "BUILD_COVERAGE enables BUILD_TEST")
    set(BUILD_TEST ON PARENT_SCOPE)
  endif()

  if(BUILD_FUZZ)
    if(NOT BUILD_TEST)
      message(STATUS "BUILD_FUZZ enables BUILD_TEST")
      set(BUILD_TEST ON PARENT_SCOPE)
    endif()
    if(NOT BUILD_ASAN)
      message(STATUS "BUILD_FUZZ enables BUILD_ASAN")
      set(BUILD_ASAN ON PARENT_SCOPE)
    endif()
  endif()

  if(NOT is_multi_config AND (BUILD_ASAN OR BUILD_FUZZ) AND
     NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(WARNING "ASan and Fuzz require Debug; selecting Debug")
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
  endif()
endfunction()
