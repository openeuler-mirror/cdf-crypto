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

#include "gtest/gtest.h"

#include "cdf/cli/cmd.h"

namespace cdf::test {

TEST(CmdManagerTest, RegistersSupportedCommands)
{
    CmdManager manager;
    ASSERT_EQ(manager.Initialize(), CryptionToolRc::OK);
    for (const char *name : {"--encrypt", "--reEncrypt", "--createkey", "--displaykey", "--removekey"}) {
        EXPECT_NE(manager.GetHandler(name), nullptr) << name;
    }
    EXPECT_EQ(manager.GetHandler("--unknown"), nullptr);
}

} // namespace cdf::test
