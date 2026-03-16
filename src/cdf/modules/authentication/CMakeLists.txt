set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES})

add_subdirectory(jwt)
add_subdirectory(kerberos)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)
