# ------------------------------------------------------------------------------
# Configure the build process of rapidjson
# ------------------------------------------------------------------------------

if(NOT ENABLE_DOWNLOAD_DEPENDENCY)
  # Use system-installed rapidjson from RPM
  add_library(librapidjson INTERFACE)
  target_include_directories(librapidjson SYSTEM INTERFACE /usr/include)
  add_library(Dependency::rapidjson ALIAS librapidjson)
else()
  ExternalProject_Add(rapidjson
          GIT_REPOSITORY https://gitcode.com/GitHub_Trending/ra/rapidjson.git
          GIT_TAG master
          GIT_SUBMODULES_RECURSE Off
          GIT_SUBMODULES ""
          GIT_SHALLOW On
          PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
          CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
          -DCMAKE_SKIP_RPATH=True
          -DCMAKE_POLICY_VERSION_MINIMUM=3.5)

  add_library(librapidjson INTERFACE)
  target_include_directories(librapidjson SYSTEM INTERFACE
    ${CMAKE_DEPENDENCY_INCLUDEDIR})
  add_dependencies(librapidjson rapidjson)
  add_library(Dependency::rapidjson ALIAS librapidjson)
endif()
