# ------------------------------------------------------------------------------
# Configure the build process of secodefuzz
# ------------------------------------------------------------------------------

if(ENABLE_DOWNLOAD_DEPENDENCY)
  set(DOWNLOAD_ARGS
      GIT_REPOSITORY
      https://codehub-dg-y.huawei.com/software-engineering-research-community/fuzz/secodefuzz.git
      GIT_TAG
      v2.4.8
      GIT_SHALLOW
      On)
else()
  set(DOWNLOAD_ARGS SOURCE_DIR ${CMAKE_DEPENDENCY_SRCDIR}/secodefuzz
                    DOWNLOAD_COMMAND "")
endif()

ExternalProject_Add(
  secodefuzz
  ${DOWNLOAD_ARGS}
  PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
  CMAKE_ARGS # NOTE this is xxxxing wired why they are not following standards
             -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
  BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} Secodefuzz
  INSTALL_COMMAND mkdir -p ${CMAKE_DEPENDENCY_INCLUDEDIR}/secodefuzz
  COMMAND cp -af Secodefuzz/secodeFuzz.h
          ${CMAKE_DEPENDENCY_INCLUDEDIR}/secodefuzz
  COMMAND cp -af examples/xml-lib/libxml2-2.6.26/include/libxml
          ${CMAKE_DEPENDENCY_INCLUDEDIR}
  COMMAND cp -af examples/out-bin-x64/libSecodefuzz.a ${CMAKE_DEPENDENCY_LIBDIR}
  BUILD_IN_SOURCE On
  EXCLUDE_FROM_ALL On
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

import_static_lib_from(libsecodefuzz secodefuzz)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::secodefuzz ALIAS libsecodefuzz)
