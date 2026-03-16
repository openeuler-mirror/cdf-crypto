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

namespace cdf {
const int STDOUT_TYPE = 0;
const int FILE_TYPE = 1;
const int32_t DEFAULT_ROTATION_FILE_SIZE = 20 * 1024 * 1024;
const int32_t DEFAULT_ROTATION_FILE_COUNT = 20;

enum class LogLevel {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,   // log level debug
    LOG_LEVEL_INFO = 2,    // log level info
    LOG_LEVEL_WARN = 3,    // log level warn
    LOG_LEVEL_ERROR = 4,   // log level error
    LOG_LEVEL_CRITICAL = 5 // log level critical
};

using LogLevelCheck = EnumCheck<LogLevel,                  //
                                LogLevel::LOG_LEVEL_TRACE, //
                                LogLevel::LOG_LEVEL_DEBUG, //
                                LogLevel::LOG_LEVEL_INFO,  //
                                LogLevel::LOG_LEVEL_WARN,  //
                                LogLevel::LOG_LEVEL_ERROR, //
                                LogLevel::LOG_LEVEL_CRITICAL>;

class Logger {
public:
    using ExternalLogFunction = void (*)(int level, const char *msg);

    static Logger *Instance()
    {
        static Logger logger;
        return &logger;
    }

    /**
     * @brief  设置自定义日志函数
     * @return void
     */
    bool SetExternalLogFunction(ExternalLogFunction func);

    void Log(int level, const std::ostringstream &oss);
    Logger(const Logger &) = delete;
    Logger(Logger &&) = delete;
    Logger &operator=(const Logger &) = delete;
    Logger &operator=(Logger &&) = delete;

    ~Logger()
    {
        logFunction_ = nullptr;
    }

private:
    Logger() = default;
    ExternalLogFunction logFunction_ = nullptr;
};

} // namespace cdf
