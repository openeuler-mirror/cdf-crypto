# ------------------------------------------------------------------------------
# Configure the build process of rapidjson
# ------------------------------------------------------------------------------

if(ENABLE_DOWNLOAD_DEPENDENCY)
  set(DOWNLOAD_ARGS
      GIT_REPOSITORY
      https://gitcode.com/gh_mirrors/rap/rapidjson.git
      GIT_TAG master
      GIT_SUBMODULES_RECURSE
      Off
      GIT_SHALLOW
      On)
else()
  set(DOWNLOAD_ARGS SOURCE_DIR ${CMAKE_DEPENDENCY_SRCDIR}/rapidjson
                    DOWNLOAD_COMMAND "")
endif()

ExternalProject_Add(
  rapidjson
  ${DOWNLOAD_ARGS}
  GIT_SUBMODULES "" # HACK
  PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
             -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_SKIP_RPATH=True
             -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
  EXCLUDE_FROM_ALL On
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

add_library(librapidjson INTERFACE)
target_include_directories(librapidjson
                           INTERFACE ${CMAKE_DEPENDENCY_INCLUDEDIR})
add_dependencies(librapidjson rapidjson)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::rapidjson ALIAS librapidjson)
