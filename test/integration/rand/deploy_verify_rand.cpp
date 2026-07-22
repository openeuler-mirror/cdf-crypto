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
/**
* @brief Deployment verification program for the rand module.
* @details Built as an independent executable linked with the CDF library.
* It depends only on the C++ standard library and exported rand APIs.
*/

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "cdf/modules/rand/rand.h"

static const char K_PWD_ALL_CHARS[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "`~!@#$%^&*()-_=+\\|[]{};:'\" ,<.>/?";
static constexpr size_t K_PWD_ALL_CHARS_LEN = sizeof(K_PWD_ALL_CHARS) - 1;
static constexpr int K_WAIT_MS = 1100;

static int g_failures = 0;

static void Check(bool condition, const std::string &message, const char *file, int line)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << " [" << file << ":" << line << "]" << std::endl;
        ++g_failures;
        return;
    }
    std::cout << "PASS: " << message << std::endl;
}

static void V1_AutoInitAndGenerate()
{
    uint8_t buf1[64];
    uint8_t buf2[64];
    cdf::RandDeinit();
    Check(cdf::GetRand(buf1, 64) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V1: auto-init GetRand#1",
          __FILE__, __LINE__);
    Check(cdf::GetRand(buf2, 64) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V1: auto-init GetRand#2",
          __FILE__, __LINE__);
    Check(std::memcmp(buf1, buf2, 64) != 0, "V1: two outputs differ", __FILE__, __LINE__);
    cdf::RandDeinit();
}

static void V2_AllDrbgTypes()
{
    const char *types[] = {"CTR-DRBG", "HASH-DRBG", "HMAC-DRBG"};
    for (auto drbg : types) {
        cdf::RandDeinit();
        cdf::RandConfig cfg;
        cfg.drbgType = drbg;
        std::string tag = std::string("V2: Init ") + drbg;
        Check(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag, __FILE__, __LINE__);
        uint8_t buf[32];
        tag = std::string("V2: GetRand ") + drbg;
        Check(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag, __FILE__, __LINE__);
        cdf::RandHealthStatus st;
        Check(cdf::GetRandHealthStatus(st) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK,
              std::string("V2: healthStatus ") + drbg, __FILE__, __LINE__);
        Check(st.isHealthy, std::string("V2: isHealthy ") + drbg, __FILE__, __LINE__);
    }
    cdf::RandDeinit();
}

static void V3_SecurityStrengthMapping()
{
    struct TestCase {
        const char *drbg;
        uint32_t strength;
    };
    TestCase cases[] = {
        {"CTR-DRBG", 128}, {"CTR-DRBG", 192}, {"CTR-DRBG", 256},
        {"HASH-DRBG", 128}, {"HASH-DRBG", 192}, {"HASH-DRBG", 256},
        {"HMAC-DRBG", 128}, {"HMAC-DRBG", 192}, {"HMAC-DRBG", 256},
    };
    for (auto c : cases) {
        cdf::RandDeinit();
        cdf::RandConfig cfg;
        cfg.drbgType = c.drbg;
        cfg.securityStrength = c.strength;
        std::string tag = std::string("V3: ") + c.drbg + "/" + std::to_string(c.strength);
        Check(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag, __FILE__, __LINE__);
        uint8_t buf[32];
        Check(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag + " generate",
              __FILE__, __LINE__);
    }
    cdf::RandDeinit();
}

static void V4_PredictionResistance()
{
    cdf::RandDeinit();
    cdf::RandConfig cfg;
    cfg.predictionResistance = true;
    Check(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V4: init", __FILE__, __LINE__);
    bool different = false;
    for (int retry = 0; retry < 5 && !different; ++retry) {
        uint8_t a[64];
        uint8_t b[64];
        if (cdf::GetRand(a, 64) != cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            continue;
        }
        if (cdf::GetRand(b, 64) != cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            continue;
        }
        different = (std::memcmp(a, b, 64) != 0);
    }
    Check(different, "V4: predictionResistance produces different output", __FILE__, __LINE__);
    cdf::RandDeinit();
}

static void V5_HealthCheck()
{
    cdf::RandDeinit();
    cdf::RandConfig cfg;
    cfg.healthCheckInterval = 1000;
    Check(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V5: init", __FILE__, __LINE__);
    uint8_t buf[32];
    Check(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V5: first GetRand",
          __FILE__, __LINE__);
    std::this_thread::sleep_for(std::chrono::milliseconds(K_WAIT_MS));
    Check(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK,
          "V5: second GetRand triggers health check", __FILE__, __LINE__);
    cdf::RandHealthStatus st;
    Check(cdf::GetRandHealthStatus(st) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V5: healthStatus",
          __FILE__, __LINE__);
    Check(st.isHealthy, "V5: isHealthy", __FILE__, __LINE__);
    Check(st.entropySufficient, "V5: entropySufficient", __FILE__, __LINE__);
    Check(st.errorCount == 0U, "V5: errorCount=0", __FILE__, __LINE__);
    cdf::RandDeinit();
}

static void V6_ConcurrentStress()
{
    cdf::RandDeinit();
    Check(cdf::RandInit() == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V6: init", __FILE__, __LINE__);
    const int kN = 4;
    const int kM = 500;
    std::atomic<int> errors{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kN; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < kM; ++j) {
                uint8_t buf[64];
                if (cdf::GetRand(buf, 64) != cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
                    errors.fetch_add(1);
                }
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }
    Check(errors.load() == 0, "V6: concurrent stress no errors", __FILE__, __LINE__);
    cdf::RandDeinit();
}

static void V7_DeinitReinitCycle()
{
    for (int cycle = 0; cycle < 5; ++cycle) {
        cdf::RandDeinit();
        std::string tag = "V7: reinit cycle " + std::to_string(cycle);
        Check(cdf::RandInit() == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag, __FILE__, __LINE__);
        uint8_t buf[32];
        Check(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag + " GetRand",
              __FILE__, __LINE__);
        Check(cdf::GetSecurePwd(buf, 8) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag + " SecurePwd",
              __FILE__, __LINE__);
    }
    cdf::RandDeinit();
}

static void V8_SecurePwdQuality()
{
    cdf::RandDeinit();
    Check(cdf::RandInit() == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V8: init", __FILE__, __LINE__);
    for (uint32_t len = 8; len <= 32; ++len) {
        std::vector<uint8_t> pwd(len);
        std::string tag = "V8: securePwd len=" + std::to_string(len);
        Check(cdf::GetSecurePwd(pwd.data(), len) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag,
              __FILE__, __LINE__);
        for (uint32_t i = 0; i < len; ++i) {
            bool valid = false;
            for (size_t j = 0; j < K_PWD_ALL_CHARS_LEN; ++j) {
                if (pwd[i] == static_cast<uint8_t>(K_PWD_ALL_CHARS[j])) {
                    valid = true;
                    break;
                }
            }
            Check(valid, tag + " char[" + std::to_string(i) + "]", __FILE__, __LINE__);
        }
    }
    cdf::RandDeinit();
}

int main()
{
    std::cout << "=== Deploy Verify: Rand Module ===" << std::endl;

    V1_AutoInitAndGenerate();
    V2_AllDrbgTypes();
    V3_SecurityStrengthMapping();
    V4_PredictionResistance();
    V5_HealthCheck();
    V6_ConcurrentStress();
    V7_DeinitReinitCycle();
    V8_SecurePwdQuality();

    std::cout << std::endl;
    if (g_failures == 0) {
        std::cout << "ALL PASSED (8/8)" << std::endl;
        return 0;
    }
    std::cout << g_failures << " FAILURE(S)" << std::endl;
    return 1;
}
