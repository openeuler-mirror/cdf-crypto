# Copyright (C) 2024 by huawei

if(NOT ENABLE_DOWNLOAD_DEPENDENCY)
  # Use system-installed openssl from RPM
  find_package(OpenSSL REQUIRED)
  add_library(Dependency::openssl ALIAS OpenSSL::SSL)
else()
  ExternalProject_Add(
    openssl
    GIT_REPOSITORY https://gitcode.com/GitHub_Trending/ope/openssl.git
    GIT_TAG openssl-3.0.9
    GIT_SUBMODULES ""
    GIT_SHALLOW On
    PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
    CONFIGURE_COMMAND ./Configure no-legacy no-weak-ssl-ciphers no-tests no-ui-console
      no-shared no-makedepend --release --libdir=${CMAKE_INSTALL_LIBDIR}
      --prefix=${CMAKE_DEPENDENCY_INSTALL_PREFIX} -w
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE On
    EXCLUDE_FROM_ALL On)

  import_static_lib_from(libcrypto openssl)
  add_library(Dependency::openssl ALIAS libcrypto)
endif()