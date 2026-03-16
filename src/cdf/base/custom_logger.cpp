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

#include "cdf/base/custom_logger.h"

#include <iostream>
#include <string>

#include "cdf/base/ccsec_logger.h"

namespace cdf {

namespace {
constexpr int DEFAULT_STR_TIME_LEN = 24;
}

void Logger::Log(int level, const std::ostringstream &oss)
{
    if (logFunction_ != nullptr) {
        logFunction_(level, oss.str().c_str());
    }
}

bool Logger::SetExternalLogFunction(ExternalLogFunction func)
{
    if (func == nullptr) {
        fprintf(stderr, "Failed to set external log function as logfunc is nullptr");
        return false;
    }
    logFunction_ = *func;
    return true;
}

} // namespace cdf
