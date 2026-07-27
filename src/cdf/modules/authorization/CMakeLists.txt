file(GLOB SRC_CPP *.cpp)

set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES} ${SRC_CPP})

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

cdf_install_headers(
  "${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/authorization"
  ${CMAKE_CURRENT_LIST_DIR}/whitelist_authorization.h
  ${CMAKE_CURRENT_LIST_DIR}/error_code.h)
