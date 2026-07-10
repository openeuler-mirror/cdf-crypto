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

# 过滤掉 -Werror 等会导致 gtest 构建失败的 flags
string(REPLACE "-Werror" "" GTEST_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(REPLACE "-Wmaybe-uninitialized" "" GTEST_CXX_FLAGS "${GTEST_CXX_FLAGS}")

ExternalProject_Add(
  gtest
  ${DOWNLOAD_ARGS}
  PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
             -DCMAKE_CXX_FLAGS=${GTEST_CXX_FLAGS} -DCMAKE_SKIP_RPATH=True
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
