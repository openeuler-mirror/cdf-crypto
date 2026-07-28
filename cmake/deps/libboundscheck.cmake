if(NOT ENABLE_DOWNLOAD_DEPENDENCY)
    # Use system-installed libboundscheck from RPM
    add_library(libboundscheck-itf INTERFACE)
    target_include_directories(libboundscheck-itf SYSTEM INTERFACE /usr/include)
    target_link_directories(libboundscheck-itf INTERFACE /usr/lib64)
    target_link_libraries(libboundscheck-itf INTERFACE /usr/lib64/libboundscheck.so)
    add_library(Dependency::secure_c ALIAS libboundscheck-itf)
else()
    ExternalProject_Add(libboundscheck-src
            GIT_REPOSITORY https://atomgit.com/openeuler/libboundscheck.git
            GIT_TAG master
            GIT_SHALLOW On
            PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
            CONFIGURE_COMMAND ""
            BUILD_COMMAND "${CDF_NATIVE_MAKE_EXECUTABLE}"
            UPDATE_COMMAND ""
            INSTALL_COMMAND mkdir -p ${CMAKE_DEPENDENCY_INCLUDEDIR} ${CMAKE_DEPENDENCY_LIBDIR}
            COMMAND cp -af include/securec.h include/securectype.h ${CMAKE_DEPENDENCY_INCLUDEDIR}
            COMMAND cp -af lib/libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_DEPENDENCY_LIBDIR}
            BUILD_IN_SOURCE On
            EXCLUDE_FROM_ALL true)

    add_library(libboundscheck-itf INTERFACE)
    target_link_directories(libboundscheck-itf INTERFACE ${CMAKE_DEPENDENCY_LIBDIR})
    target_link_libraries(libboundscheck-itf INTERFACE libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX})
    add_dependencies(libboundscheck-itf libboundscheck-src)
    add_library(Dependency::secure_c ALIAS libboundscheck-itf)
endif()
