# ------------------------------------------------------------------------------
# Configure the build process of gtest
# ------------------------------------------------------------------------------

if(ENABLE_DOWNLOAD_DEPENDENCY)
  set(DOWNLOAD_ARGS
      GIT_REPOSITORY
      https://atomgit.com/GitHub_Trending/go/googletest.git
      GIT_TAG v1.14.0 GIT_SHALLOW On)
else()
  set(DOWNLOAD_ARGS SOURCE_DIR ${CMAKE_DEPENDENCY_SRCDIR}/gtest
                    DOWNLOAD_COMMAND "")
endif()

ExternalProject_Add(
  gtest
  ${DOWNLOAD_ARGS}
  PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
             -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_SKIP_RPATH=True
  BUILD_BYPRODUCTS
    "${CMAKE_DEPENDENCY_LIBDIR}/libgtest${CMAKE_STATIC_LIBRARY_SUFFIX}"
    "${CMAKE_DEPENDENCY_LIBDIR}/libgtest_main${CMAKE_STATIC_LIBRARY_SUFFIX}"
  EXCLUDE_FROM_ALL On
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

import_static_lib_from(libgtest gtest)
import_static_lib_from(libgtest_main gtest)

target_link_libraries(libgtest_main INTERFACE libgtest)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::gtest ALIAS libgtest_main)
