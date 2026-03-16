# Copyright (C) 2024 by huawei.com

# ------------------------------------------------------------------------------
# Configure the build process of huawei secure c library
# ------------------------------------------------------------------------------
if(ENABLE_DOWNLOAD_DEPENDENCY)
    set(DOWNLOAD_ARGS
            GIT_REPOSITORY
            https://atomgit.com/openeuler/libboundscheck.git
            GIT_TAG master GIT_SHALLOW On)
else()
    set(DOWNLOAD_ARGS SOURCE_DIR ${CMAKE_DEPENDENCY_SRCDIR}/libboundscheck
            DOWNLOAD_COMMAND "")
endif()

ExternalProject_Add(
        libboundscheck
        ${DOWNLOAD_ARGS}
        PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
        CONFIGURE_COMMAND "" # no configure
        UPDATE_COMMAND "" # no update process
        BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
        INSTALL_COMMAND mkdir -p ${CMAKE_DEPENDENCY_INCLUDEDIR}/securec
        COMMAND cp -af include/. ${CMAKE_DEPENDENCY_INCLUDEDIR}/securec
        COMMAND cp -af lib/. ${CMAKE_DEPENDENCY_LIBDIR}
        EXCLUDE_FROM_ALL Off
        BUILD_IN_SOURCE On
        LOG_DOWNLOAD On
        LOG_CONFIGURE On
        LOG_BUILD On
        LOG_INSTALL On)

add_library(libboundscheck-itf INTERFACE)
target_link_directories(libboundscheck-itf INTERFACE ${CMAKE_DEPENDENCY_LIBDIR})
target_link_libraries(libboundscheck-itf
        INTERFACE libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX})
add_dependencies(libboundscheck-itf libboundscheck-src)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::secure_c ALIAS libboundscheck-itf)

install(FILES ${CMAKE_DEPENDENCY_LIBDIR}/libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PERMISSIONS OWNER_READ)

add_compile_options(-lboundscheck)
