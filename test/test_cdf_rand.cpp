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

#include "gtest/gtest.h"
#include "securec.h"
#include "test_utils.h"

#include "cdf/modules/rand/rand.h"

namespace cdf::test {

class TestCDFRand : public ::testing::Test {};


TEST_F(TestCDFRand, RandInit_True)
{
    uint32_t plainTextLen = 10;
    uint8_t plainText[plainTextLen] = {0};
    RandDeinit();
    int32_t ret = GetRand(plainText, plainTextLen);
    EXPECT_TRUE(ret != CCSEC_CRYPT_OK);
    ret = RandInit();
    EXPECT_TRUE(ret == CCSEC_CRYPT_OK);
    ret = GetRand(nullptr, plainTextLen);
    EXPECT_TRUE(ret == CCSEC_CRYPT_PARAM_INVALID);
    ret = GetRand(plainText, plainTextLen);
    EXPECT_TRUE(ret == CCSEC_CRYPT_OK);
    ret = RandInit();
    EXPECT_TRUE(ret == CCSEC_CRYPT_OK);
    RandDeinit();
    ret = RandInit();
    EXPECT_TRUE(ret == CCSEC_CRYPT_OK);
    (void)memset_s(plainText, plainTextLen, 0, plainTextLen);
}

TEST_F(TestCDFRand, GetSecurePwd_OK)
{
    uint32_t pwdLen = 8;
    uint8_t pwdBuffer[pwdLen] = {0};
    EXPECT_EQ(GetSecurePwd(pwdBuffer, pwdLen), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    uint32_t pwdLen2 = 32;
    uint8_t pwdBuffer2[pwdLen2] = {0};
    EXPECT_EQ(GetSecurePwd(pwdBuffer2, pwdLen2), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
}

TEST_F(TestCDFRand, GetSecurePwd_InvalidParams)
{
    // 长度过小
    uint32_t pwdLen = 7;
    uint8_t pwdBuffer[pwdLen] = {0};
    EXPECT_EQ(GetSecurePwd(pwdBuffer, pwdLen), CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
    // 长度过大
    uint32_t pwdLen2 = 33;
    uint8_t pwdBuffer2[pwdLen2] = {0};
    EXPECT_EQ(GetSecurePwd(pwdBuffer2, pwdLen2), CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
    // 空指针
    uint32_t pwdLen3 = 10;
    EXPECT_EQ(GetSecurePwd(nullptr, pwdLen3), CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
}

} // namespace cdf::test