#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_AUTHENTICATION)
    list(APPEND CDF_SOURCE_FILES
            ${CMAKE_CURRENT_LIST_DIR}/krb5_wrapper.cpp)
endif()

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)
