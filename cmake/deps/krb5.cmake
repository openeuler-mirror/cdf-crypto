# Copyright (C) 2024 by huawei.com

# ------------------------------------------------------------------------------
# Configure the build process of kerbros 5 library
# ------------------------------------------------------------------------------

if(ENABLE_DOWNLOAD_DEPENDENCY)
  set(DOWNLOAD_ARGS
      URL https://kerberos.org/dist/krb5/1.22/krb5-1.22.2.tar.gz
      DOWNLOAD_NAME krb5-1.22.2.tar.gz)
else()
  set(DOWNLOAD_ARGS SOURCE_DIR ${CMAKE_DEPENDENCY_SRCDIR}/krb5 DOWNLOAD_COMMAND
                    "")
endif()

ExternalProject_Add(
  krb5
  ${DOWNLOAD_ARGS}
  PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
  UPDATE_COMMAND "" # HACK no update process
  CONFIGURE_COMMAND autoheader
  COMMAND autoconf
  # HACK see: https://krbdev.mit.edu/rt/Ticket/History.html?id=8996#txn-98809
  # HACK normal make first
  COMMAND
#    ./configure YACC=bison\ -y LDFLAGS=-Wl,-z,now,-z,noexecstack,-z,relro,-s CFLAGS=-fstack-protector-strong\ -ftrapv\ -fPIC\ -D_FORTIFY_SOURCE=2\ -O2\ -Wno-error\ -Wno-incompatible-pointer-types --prefix=${CMAKE_DEPENDENCY_INSTALL_PREFIX} --libdir=${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR} --disable-rpath --without-keyutils
    ./configure LDFLAGS=-Wl,-z,now,-z,noexecstack,-z,relro,-s
    CFLAGS=-fstack-protector-strong\ -ftrapv\ -fPIC\ -D_FORTIFY_SOURCE=2\ -O2
    --prefix=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
    --libdir=${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
    --disable-rpath --without-keyutils
  # HACK run make
  BUILD_COMMAND make
  # HACK re-configure with disabled shared lib
  # COMMAND
  #   ./configure LDFLAGS=-Wl,-z,now,-z,noexecstack,-z,relro,-s
  #   CFLAGS=-fstack-protector-strong\ -ftrapv\ -fPIC\ -D_FORTIFY_SOURCE=2\ -O2
  #   --prefix=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
  #   --libdir=${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
  #   --disable-rpath --without-keyutilsa --enable-static --disable-shared
  # # HACK run make again
  # COMMAND make
  INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
  SOURCE_SUBDIR src
  EXCLUDE_FROM_ALL On
  BUILD_IN_SOURCE On
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

# main lib
import_shared_lib_from(libkrb5 krb5)

# other
import_shared_lib_from(libgssapi_krb5 krb5)
import_shared_lib_from(libcom_err krb5)
import_shared_lib_from(libkrb5support krb5)
import_shared_lib_from(libk5crypto krb5)

# lib does not need
# import_shared_lib_from(libgssrpc krb5)
# import_shared_lib_from(libkadm5clnt krb5)
# import_shared_lib_from(libkadm5srv krb5)
# import_shared_lib_from(libkdb5 krb5)
# import_shared_lib_from(libkrad krb5)

target_link_libraries(libkrb5 INTERFACE libgssapi_krb5 libcom_err
                                        libkrb5support libk5crypto)

install(
  FILES
    ${CMAKE_DEPENDENCY_LIBDIR}/libkrb5${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${CMAKE_DEPENDENCY_LIBDIR}/libkrb5${CMAKE_SHARED_LIBRARY_SUFFIX}.3
    ${CMAKE_DEPENDENCY_LIBDIR}/libkrb5${CMAKE_SHARED_LIBRARY_SUFFIX}.3.3
    ${CMAKE_DEPENDENCY_LIBDIR}/libgssapi_krb5${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${CMAKE_DEPENDENCY_LIBDIR}/libgssapi_krb5${CMAKE_SHARED_LIBRARY_SUFFIX}.2
    ${CMAKE_DEPENDENCY_LIBDIR}/libgssapi_krb5${CMAKE_SHARED_LIBRARY_SUFFIX}.2.2
    ${CMAKE_DEPENDENCY_LIBDIR}/libcom_err${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${CMAKE_DEPENDENCY_LIBDIR}/libcom_err${CMAKE_SHARED_LIBRARY_SUFFIX}.3
    ${CMAKE_DEPENDENCY_LIBDIR}/libcom_err${CMAKE_SHARED_LIBRARY_SUFFIX}.3.0
    ${CMAKE_DEPENDENCY_LIBDIR}/libkrb5support${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${CMAKE_DEPENDENCY_LIBDIR}/libkrb5support${CMAKE_SHARED_LIBRARY_SUFFIX}.0
    ${CMAKE_DEPENDENCY_LIBDIR}/libkrb5support${CMAKE_SHARED_LIBRARY_SUFFIX}.0.1
    ${CMAKE_DEPENDENCY_LIBDIR}/libk5crypto${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${CMAKE_DEPENDENCY_LIBDIR}/libk5crypto${CMAKE_SHARED_LIBRARY_SUFFIX}.3
    ${CMAKE_DEPENDENCY_LIBDIR}/libk5crypto${CMAKE_SHARED_LIBRARY_SUFFIX}.3.1
  DESTINATION ${CMAKE_INSTALL_LIBDIR})

# -----------------------------
# Alias Target for External Use
# -----------------------------

add_library(Dependency::krb5 ALIAS libkrb5)
