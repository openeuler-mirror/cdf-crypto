set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES}
                          ${CMAKE_CURRENT_LIST_DIR}/km_cryptor.cpp
                          ${CMAKE_CURRENT_LIST_DIR}/key_manager_factory.cpp)

add_subdirectory(openbao)
add_subdirectory(vault)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

cdf_install_headers(
  "${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/key_management"
  ${CMAKE_CURRENT_LIST_DIR}/define.h
  ${CMAKE_CURRENT_LIST_DIR}/km_cryptor.h
  ${CMAKE_CURRENT_LIST_DIR}/key_manager_factory.h
  ${CMAKE_CURRENT_LIST_DIR}/key_manager.h)
