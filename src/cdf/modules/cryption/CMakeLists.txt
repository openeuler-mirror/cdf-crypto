# 根据选项编译不同的源文件
set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/native_cryptor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/hmac.cpp
    ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
    ${CMAKE_CURRENT_LIST_DIR}/native_cryptor_engine.cpp)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)


cdf_install_headers(
  "${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/cryption"
  ${CMAKE_CURRENT_LIST_DIR}/native_cryptor.h
  ${CMAKE_CURRENT_LIST_DIR}/define.h
  ${CMAKE_CURRENT_LIST_DIR}/native_cryptor_def.h
  ${CMAKE_CURRENT_LIST_DIR}/hash.h)
