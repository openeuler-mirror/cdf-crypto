# Copyright (C) 2024 by huawei.com

if(NOT ENABLE_DOWNLOAD_DEPENDENCY)
  # Use system-installed krb5 from RPM
  add_library(libkrb5 INTERFACE)
  target_include_directories(libkrb5 INTERFACE /usr/include)
  target_link_libraries(libkrb5 INTERFACE
    /usr/lib64/libkrb5.so
    /usr/lib64/libgssapi_krb5.so
    /usr/lib64/libcom_err.so
    /usr/lib64/libkrb5support.so
    /usr/lib64/libk5crypto.so)
  add_library(Dependency::krb5 ALIAS libkrb5)
else()
  ExternalProject_Add(
    krb5
    URL https://kerberos.org/dist/krb5/1.22/krb5-1.22.2.tar.gz
    DOWNLOAD_NAME krb5-1.22.2.tar.gz
    PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND autoheader && autoconf && ./configure
      LDFLAGS=-Wl,-z,now,-z,noexecstack,-z,relro,-s
      CFLAGS=-fstack-protector-strong\ -ftrapv\ -fPIC\ -D_FORTIFY_SOURCE=2\ -O2
      --prefix=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
      --libdir=${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
      --disable-rpath --without-keyutils
    BUILD_COMMAND make
    INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
    SOURCE_SUBDIR src
    EXCLUDE_FROM_ALL On
    BUILD_IN_SOURCE On)

  import_shared_lib_from(libkrb5 krb5)
  target_link_libraries(libkrb5 INTERFACE libgssapi_krb5 libcom_err
                                          libkrb5support libk5crypto)
  add_library(Dependency::krb5 ALIAS libkrb5)
endif()