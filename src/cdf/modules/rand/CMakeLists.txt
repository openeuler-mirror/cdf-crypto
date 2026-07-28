set(CDF_SOURCE_FILES
        ${CDF_SOURCE_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/rand.cpp)

set(CDF_SOURCE_FILES
        ${CDF_SOURCE_FILES}
        PARENT_SCOPE)

cdf_install_headers(
  "${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/rand"
  ${CMAKE_CURRENT_LIST_DIR}/rand.h)
