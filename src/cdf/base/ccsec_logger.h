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

#include <sys/time.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

#include "cdf/base/common_define.h"
#include "cdf/base/custom_logger.h"

#ifndef CCSEC_LIKELY
#define CCSEC_LIKELY(x) (__builtin_expect(!!(x), 1) != 0)
#endif

#ifndef CCSEC_UNLIKELY
#define CCSEC_UNLIKELY(x) (__builtin_expect(!!(x), 0) != 0)
#endif

// macro for log
#ifndef CCSEC_LOG_FILENAME
#define CCSEC_LOG_FILENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

// define our logger
#ifndef LCOV_IGNORE
#define CCSEC_LOG(level, args)                                                                                     \
    do {                                                                                                          \
        std::ostringstream ossLog;                                                                                \
        ossLog << "[CCSEC " << CCSEC_LOG_FILENAME << ":" << __LINE__ << "] " << args;                             \
        auto logger = ::cdf::Logger::Instance();                                                             \
        if (logger != nullptr) {                                                                                  \
            logger->Log(level, ossLog); \
        }                                                                                                         \
    } while (0)
#else
#define CCSEC_LOG(level, ...)
#endif

#define CCSEC_LOG_TRACE(...) CCSEC_LOG(static_cast<int>(cdf::LogLevel::LOG_LEVEL_TRACE), __VA_ARGS__)
#define CCSEC_LOG_DEBUG(...) CCSEC_LOG(static_cast<int>(cdf::LogLevel::LOG_LEVEL_DEBUG), __VA_ARGS__)
#define CCSEC_LOG_INFO(...) CCSEC_LOG(static_cast<int>(cdf::LogLevel::LOG_LEVEL_INFO), __VA_ARGS__)
#define CCSEC_LOG_WARN(...) CCSEC_LOG(static_cast<int>(cdf::LogLevel::LOG_LEVEL_WARN), __VA_ARGS__)
#define CCSEC_LOG_ERROR(...) CCSEC_LOG(static_cast<int>(cdf::LogLevel::LOG_LEVEL_ERROR), __VA_ARGS__)

#define CCSEC_ASSERT_LOG_RETURN(args, ret)   \
    if (CCSEC_UNLIKELY(!(args))) {           \
        CCSEC_LOG_ERROR("Assert " << #args); \
        return (ret);                        \
    }

#define CCSEC_ASSERT_LOG_RETURN_VOID(args)   \
    if (CCSEC_UNLIKELY(!(args))) {           \
        CCSEC_LOG_ERROR("Assert " << #args); \
        return;                              \
    }
