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

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <thread>
#include <vector>
#include "gtest/gtest.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "openssl/provider.h"
#include "securec.h"
#include "test_log_utils.h"

#include "cdf/base/custom_logger.h"
#include "cdf/modules/rand/rand.h"

namespace cdf::test {

class TestCDFRand : public ::testing::Test {};


TEST_F(TestCDFRand, RandInit_True)
{
    uint32_t plainTextLen = 10;
    uint8_t plainText[plainTextLen] = {0};
    RandDeinit();
    int32_t ret = GetRand(plainText, plainTextLen);
    // 自动初始化机制：GetRand 会自动初始化并成功
    EXPECT_EQ(ret, CCSEC_CRYPT_OK);
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

TEST_F(TestCDFRand, GetSecurePwd_CustomRetryTimes_OK)
{
    uint32_t pwdLen = 16;
    uint8_t pwdBuffer[pwdLen] = {0};
    EXPECT_EQ(GetSecurePwd(pwdBuffer, pwdLen, 1), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
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
    // 重试次数为0
    uint8_t pwdBuffer4[pwdLen3] = {0};
    EXPECT_EQ(GetSecurePwd(pwdBuffer4, pwdLen3, 0), CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
}

// ========== 自动初始化测试 ==========
class RandTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        EXPECT_TRUE(Logger::Instance()->SetExternalLogFunction(TestLogCallback));
    }

    void TearDown() override
    {
        // Perform any necessary cleanup for the test cases
    }
};

TEST_F(RandTest, AutoInit_OnFirstCall)
{
    RandDeinit();  // 确保未初始化状态

    uint8_t buf[32];
    CcsecCryptErrorCode rc = GetRand(buf, 32);

    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    // 验证生成的随机数非全零
    bool allZero = true;
    for (int i = 0; i < 32; i++) {
        if (buf[i] != 0) {
            allZero = false;
        }
    }
    EXPECT_FALSE(allZero);
}

TEST_F(RandTest, AutoInit_MultipleCalls)
{
    RandDeinit();

    uint8_t buf1[16];
    uint8_t buf2[16];

    CcsecCryptErrorCode rc1 = GetRand(buf1, 16);
    CcsecCryptErrorCode rc2 = GetRand(buf2, 16);

    EXPECT_EQ(rc1, CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    EXPECT_EQ(rc2, CcsecCryptErrorCode::CCSEC_CRYPT_OK);
}

// ========== 配置初始化测试 ==========

TEST_F(RandTest, Init_DefaultConfig_Success)
{
    RandDeinit();

    RandConfig config;
    CcsecCryptErrorCode rc = RandInit(config);

    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    RandHealthStatus status;
    GetRandHealthStatus(status);
    EXPECT_TRUE(status.isHealthy);
}

TEST_F(RandTest, Init_RepeatedInit_Idempotent)
{
    RandDeinit();

    RandConfig config1;
    CcsecCryptErrorCode rc1 = RandInit(config1);
    EXPECT_EQ(rc1, CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    RandConfig config2;
    CcsecCryptErrorCode rc2 = RandInit(config2);
    EXPECT_EQ(rc2, CcsecCryptErrorCode::CCSEC_CRYPT_OK);
}

TEST_F(RandTest, Init_InvalidDrbgType_ReturnsWithoutBlocking)
{
    RandDeinit();

    RandConfig config;
    config.drbgType = "INVALID-DRBG";
    std::promise<CcsecCryptErrorCode> resultPromise;
    auto resultFuture = resultPromise.get_future();

    std::thread([config, promise = std::move(resultPromise)]() mutable {
        promise.set_value(RandInit(config));
    }).detach();

    ASSERT_EQ(resultFuture.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_EQ(resultFuture.get(), CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
}

TEST_F(RandTest, Init_UnsupportedCustomSeedSource_Fails)
{
    RandDeinit();

    RandConfig config;
    config.seedSource = "CUSTOM";
    config.customSeedProvider = "UNSUPPORTED-SEED-SOURCE";

    EXPECT_EQ(RandInit(config), CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
}

TEST_F(RandTest, Init_CustomSeedSourceDefaultProvider_Success)
{
    RandDeinit();

    RandConfig config;
    config.seedSource = "CUSTOM";
    config.customSeedProvider = "default";

    EXPECT_EQ(RandInit(config), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    uint8_t buf[32] = {0};
    EXPECT_EQ(GetRand(buf, sizeof(buf)), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    RandDeinit();
}

TEST_F(RandTest, Init_HardwareSeedSourceRequiresAvailableJitterProvider)
{
    RandDeinit();

    RandConfig config;
    config.seedSource = "HARDWARE";

    OSSL_PROVIDER *defaultProvider = OSSL_PROVIDER_load(nullptr, "default");
    EVP_RAND *jitterRand = EVP_RAND_fetch(nullptr, "JITTER", nullptr);
    const bool jitterAvailable = jitterRand != nullptr;
    EVP_RAND_free(jitterRand);
    if (defaultProvider != nullptr) {
        OSSL_PROVIDER_unload(defaultProvider);
    }

    EXPECT_EQ(RandInit(config), jitterAvailable ? CcsecCryptErrorCode::CCSEC_CRYPT_OK
                                                : CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    RandDeinit();
}

TEST_F(RandTest, Init_ConfiguredDrbgTypes_GenerateRandom)
{
    const char *drbgTypes[] = {"CTR-DRBG", "HASH-DRBG", "HMAC-DRBG"};
    for (const char *drbgType : drbgTypes) {
        RandDeinit();

        RandConfig config;
        config.drbgType = drbgType;
        config.seedSource = "SEED-SRC";
        ASSERT_EQ(RandInit(config), CcsecCryptErrorCode::CCSEC_CRYPT_OK) << drbgType;

        RandHealthStatus st;
        ASSERT_EQ(GetRandHealthStatus(st), CcsecCryptErrorCode::CCSEC_CRYPT_OK) << drbgType;
        EXPECT_TRUE(st.isHealthy) << drbgType;
        EXPECT_TRUE(st.entropySufficient) << drbgType;

        uint8_t buf[32] = {0};
        EXPECT_EQ(GetRand(buf, sizeof(buf)), CcsecCryptErrorCode::CCSEC_CRYPT_OK) << drbgType;
    }
    RandDeinit();
}

TEST_F(RandTest, Init_FipsModeRequiresFipsProvider)
{
    RandDeinit();

    RandConfig config;
    config.fipsMode = true;

    OSSL_PROVIDER *defaultProvider = OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER *fipsProvider = OSSL_PROVIDER_load(nullptr, "fips");
    EVP_RAND *fipsDrbg = fipsProvider == nullptr ? nullptr : EVP_RAND_fetch(nullptr, "CTR-DRBG", "fips=yes");
    EVP_RAND *fipsParent = fipsProvider == nullptr ? nullptr : EVP_RAND_fetch(nullptr, "JITTER", "fips=yes");
    const bool fipsRandAvailable = fipsDrbg != nullptr && fipsParent != nullptr;
    EVP_RAND_free(fipsDrbg);
    EVP_RAND_free(fipsParent);
    if (fipsProvider != nullptr) {
        OSSL_PROVIDER_unload(fipsProvider);
    }
    if (defaultProvider != nullptr) {
        OSSL_PROVIDER_unload(defaultProvider);
    }

    EXPECT_EQ(RandInit(config), fipsRandAvailable ? CcsecCryptErrorCode::CCSEC_CRYPT_OK
                                                  : CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    RandDeinit();
}

TEST_F(RandTest, ConcurrentGetRandAndDeinit_NoCrashOrBlock)
{
    RandDeinit();
    RandConfig config;
    config.healthCheckInterval = 1;
    ASSERT_EQ(RandInit(config), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    std::atomic<uint32_t> failures{0};
    std::atomic<bool> stop{false};
    std::thread reinitThread([&config, &stop]() {
        for (uint32_t i = 0; i < 100 && !stop.load(); ++i) {
            RandDeinit();
            (void)RandInit(config);
        }
    });

    std::vector<std::thread> getRandThreads;
    for (uint32_t i = 0; i < 4; ++i) {
        getRandThreads.emplace_back([&failures]() {
            uint8_t buf[32] = {0};
            for (uint32_t j = 0; j < 100; ++j) {
                if (GetRand(buf, sizeof(buf)) != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
                    failures.fetch_add(1);
                }
            }
        });
    }

    for (auto &thread : getRandThreads) {
        thread.join();
    }
    stop.store(true);
    reinitThread.join();

    EXPECT_EQ(failures.load(), 0U);
    RandDeinit();
}

// ========== 健康状态测试 ==========

TEST_F(RandTest, HealthStatus_AfterInit_Healthy)
{
    RandDeinit();
    RandInit();

    RandHealthStatus status;
    CcsecCryptErrorCode rc = GetRandHealthStatus(status);

    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    EXPECT_TRUE(status.isHealthy);
    EXPECT_TRUE(status.entropySufficient);
    EXPECT_EQ(status.errorCount, 0U);
}

TEST_F(RandTest, HealthStatus_NotInit_Unhealthy)
{
    RandDeinit();

    RandHealthStatus status;
    GetRandHealthStatus(status);

    EXPECT_FALSE(status.isHealthy);
}

// ========== 参数校验测试 ==========

TEST_F(RandTest, GetRand_NullBuffer_Fail)
{
    RandDeinit();
    RandInit();

    CcsecCryptErrorCode rc = GetRand(nullptr, 32);
    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
}

TEST_F(RandTest, GetRand_ZeroLength_Fail)
{
    RandDeinit();
    RandInit();

    uint8_t buf[32];
    CcsecCryptErrorCode rc = GetRand(buf, 0);
    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
}

TEST_F(RandTest, GetRand_ExceedMaxLength_Fail)
{
    RandDeinit();
    RandInit();

    std::vector<uint8_t> buf(70000);
    CcsecCryptErrorCode rc = GetRand(buf.data(), 70000);
    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
}

TEST_F(RandTest, GetRand_MinLength_Success)
{
    RandDeinit();
    RandInit();

    uint8_t buf[1];
    CcsecCryptErrorCode rc = GetRand(buf, 1);
    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_OK);
}

TEST_F(RandTest, GetRand_MaxLength_Success)
{
    RandDeinit();
    RandInit();

    std::vector<uint8_t> buf(65536);
    CcsecCryptErrorCode rc = GetRand(buf.data(), 65536);
    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_OK);
}

// ========== 向后兼容测试 ==========

TEST_F(RandTest, BackwardCompat_ManualInit_Success)
{
    RandDeinit();

    CcsecCryptErrorCode rc = RandInit();
    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    uint8_t buf[32];
    rc = GetRand(buf, 32);
    EXPECT_EQ(rc, CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    RandDeinit();
}

// ========== 周期性健康检查测试 ==========

TEST_F(RandTest, HealthCheckInterval_PeriodicCheck_Enabled)
{
    RandDeinit();

    RandConfig config;
    config.healthCheckInterval = 1000; // 1秒间隔，确保测试中能触发
    ASSERT_EQ(RandInit(config), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    // 验证健康状态正常
    RandHealthStatus status;
    ASSERT_EQ(GetRandHealthStatus(status), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    EXPECT_TRUE(status.isHealthy);
    EXPECT_EQ(status.errorCount, 0U);

    // 第一次 GetRand 触发初始健康检查（记录时间）
    uint8_t buf1[32];
    EXPECT_EQ(GetRand(buf1, sizeof(buf1)), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    // 等待超过 healthCheckInterval 后再次调用，应触发周期性检查
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    uint8_t buf2[32];
    EXPECT_EQ(GetRand(buf2, sizeof(buf2)), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    // 验证生成的两次随机数不同
    bool identical = true;
    for (size_t i = 0; i < sizeof(buf1); i++) {
        if (buf1[i] != buf2[i]) {
            identical = false;
            break;
        }
    }
    EXPECT_FALSE(identical);

    RandDeinit();
}

TEST_F(RandTest, HealthCheckInterval_DefaultDisabled)
{
    RandDeinit();

    // 使用默认配置（healthCheckInterval=0）初始化
    RandConfig config;
    ASSERT_EQ(RandInit(config), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    // 验证健康状态正常
    RandHealthStatus status;
    ASSERT_EQ(GetRandHealthStatus(status), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    EXPECT_TRUE(status.isHealthy);
    EXPECT_EQ(status.errorCount, 0U);

    // 多次调用 GetRand 不应触发周期性检查（healthCheckInterval=0）
    uint8_t buf[32];
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(GetRand(buf, sizeof(buf)), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    }

    // 验证错误计数仍为0（没有因周期性检查导致错误）
    ASSERT_EQ(GetRandHealthStatus(status), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    EXPECT_EQ(status.errorCount, 0U);

    RandDeinit();
}

#ifdef CDF_RAND_TESTING
TEST_F(RandTest, HealthCheckInterval_SubSecondIntervalTriggersHealthCheck)
{
    RandDeinit();

    RandConfig config;
    config.healthCheckInterval = 10;
    ASSERT_EQ(RandInit(config), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    const uint32_t before = GetRandHealthCheckCountForTest();
    uint8_t buf[32] = {0};
    ASSERT_EQ(GetRand(buf, sizeof(buf)), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ASSERT_EQ(GetRand(buf, sizeof(buf)), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    EXPECT_GT(GetRandHealthCheckCountForTest(), before);

    RandDeinit();
}
#endif
// ========== 新增测试 (EVP_RAND 迁移) ==========

TEST_F(RandTest, SecurityStrength_Mapping)
{
    struct TestCase {
        const char *drbg;
        uint32_t strength;
        bool expectSuccess;
    };
    TestCase cases[] = {
        // CTR-DRBG: 只支持 128/192/256
        {"CTR-DRBG", 112, false},
        {"CTR-DRBG", 128, true},
        {"CTR-DRBG", 192, true},
        {"CTR-DRBG", 256, true},
        // HASH-DRBG: 支持全部 [112,256]
        {"HASH-DRBG", 112, true},
        {"HASH-DRBG", 128, true},
        {"HASH-DRBG", 192, true},
        {"HASH-DRBG", 256, true},
        // HMAC-DRBG: 支持全部 [112,256]
        {"HMAC-DRBG", 112, true},
        {"HMAC-DRBG", 128, true},
        {"HMAC-DRBG", 192, true},
        {"HMAC-DRBG", 256, true},
    };
    for (auto c : cases) {
        RandDeinit();
        RandConfig cfg;
        cfg.drbgType = c.drbg;
        cfg.securityStrength = c.strength;
        if (c.expectSuccess) {
            ASSERT_EQ(RandInit(cfg), CcsecCryptErrorCode::CCSEC_CRYPT_OK)
                << "DRBG=" << c.drbg << " strength=" << c.strength;
            uint8_t buf[32];
            EXPECT_EQ(GetRand(buf, 32), CcsecCryptErrorCode::CCSEC_CRYPT_OK)
                << "DRBG=" << c.drbg << " strength=" << c.strength;
        } else {
            EXPECT_NE(RandInit(cfg), CcsecCryptErrorCode::CCSEC_CRYPT_OK)
                << "DRBG=" << c.drbg << " strength=" << c.strength;
        }
    }
    RandDeinit();
}

TEST_F(RandTest, PredictionResistance_Enabled)
{
    RandDeinit();
    RandConfig cfg;
    cfg.predictionResistance = true;
    ASSERT_EQ(RandInit(cfg), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    uint8_t a[64];
    uint8_t b[64];
    ASSERT_EQ(GetRand(a, 64), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    ASSERT_EQ(GetRand(b, 64), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    EXPECT_NE(memcmp(a, b, 64), 0) << "predictionResistance should produce different output";

    RandDeinit();
}

TEST_F(RandTest, Isolation_FromGlobalRAND)
{
    RandDeinit();
    ASSERT_EQ(RandInit(), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    uint8_t privBuf[32];
    ASSERT_EQ(GetRand(privBuf, 32), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    uint8_t globalBuf[32];
    ASSERT_EQ(RAND_priv_bytes(globalBuf, 32), 1);

    EXPECT_NE(memcmp(privBuf, globalBuf, 32), 0);

    RandDeinit();
}

TEST_F(RandTest, Deinit_CleansUpProviders)
{
    RandDeinit();
    ASSERT_EQ(RandInit(), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    RandDeinit();

    ASSERT_EQ(RandInit(), CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    uint8_t buf[32];
    EXPECT_EQ(GetRand(buf, 32), CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    RandDeinit();
}

TEST_F(RandTest, InvalidStrength_Fails)
{
    RandDeinit();
    RandConfig cfg;

    cfg.securityStrength = 100;  // 低于最小值 112
    EXPECT_EQ(RandInit(cfg), CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);

    RandDeinit();
    cfg.securityStrength = 300;  // 高于最大值 256
    EXPECT_EQ(RandInit(cfg), CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);

    RandDeinit();
}

} // namespace cdf::test
