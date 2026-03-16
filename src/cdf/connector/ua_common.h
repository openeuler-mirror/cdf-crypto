/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#pragma once

#include <dlfcn.h>

#include "cdf/base/ccsec_logger.h"

namespace cdf {

inline void DlLoadReportError(const char *sym)
{
    std::ostringstream oss;
    oss << "Failed to load function " << (sym) << ", error " << dlerror();
    CCSEC_LOG_ERROR(oss.str());
}

#define DL_LOAD_FUNCTION(handle, type, ptr, sym) \
    do {                                         \
        auto ptr1 = dlsym((handle), (sym));      \
        if (ptr1 == nullptr) {                   \
            DlLoadReportError(sym);              \
            return -1;                           \
        }                                        \
        (ptr) = (type)ptr1;                      \
    } while (0)

} // namespace cdf
