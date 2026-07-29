if(ENABLE_DOWNLOAD_DEPENDENCY)
  set(DOWNLOAD_ARGS
      GIT_REPOSITORY
      https://gitcode.com/GitHub_Trending/ope/openssl.git
      GIT_TAG
        openssl-3.0.9
      GIT_SUBMODULES_RECURSE
      Off
      GIT_SHALLOW
      On)
else()
  set(DOWNLOAD_ARGS
      DOWNLOAD_COMMAND
        ${CMAKE_COMMAND}
        -DSOURCE_DIR=${CMAKE_DEPENDENCY_SRCDIR}/openssl
        -DDESTINATION_DIR=<SOURCE_DIR>
        -P ${PROJECT_SOURCE_DIR}/cmake/CopyGitWorktree.cmake)
endif()

ExternalProject_Add(
  openssl
  ${DOWNLOAD_ARGS}
  GIT_SUBMODULES "" # HACK
  PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
  BINARY_DIR
    ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/src/openssl-build-${ENABLE_DOWNLOAD_DEPENDENCY}
  CONFIGURE_COMMAND
    <SOURCE_DIR>/Configure no-legacy no-weak-ssl-ciphers no-tests
    no-ui-console no-shared
    no-makedepend
    --release --libdir=${CMAKE_INSTALL_LIBDIR}
    --prefix=${CMAKE_DEPENDENCY_INSTALL_PREFIX} -w
  BUILD_COMMAND "${CDF_NATIVE_MAKE_EXECUTABLE}"
  INSTALL_COMMAND "${CDF_NATIVE_MAKE_EXECUTABLE}" install
  BUILD_BYPRODUCTS
    "${CMAKE_DEPENDENCY_LIBDIR}/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}"
  EXCLUDE_FROM_ALL On
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

import_static_lib_from(libcrypto openssl)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::openssl ALIAS libcrypto)
