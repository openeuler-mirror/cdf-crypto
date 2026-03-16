/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
          * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <string>

#include "gtest/gtest.h"

#include "cdf/base/custom_logger.h"

namespace cdf::test {

class TestCDFBase : public ::testing::Test {};

TEST_F(TestCDFBase, LogFuncTest2)
{
    std::ostringstream msg;
    msg << "Hello World";

    auto *logger = ::cdf::Logger::Instance();
    if (logger != nullptr) {
        logger->Log(static_cast<int>(LogLevel::LOG_LEVEL_INFO), msg);
    }
}

} // namespace cdf::test
