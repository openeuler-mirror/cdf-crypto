/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
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

static const char kPwdAllChars[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "`~!@#$%^&*()-_=+\\|[]{};:'\" ,<.>/?";
static constexpr size_t kPwdAllCharsLen = sizeof(kPwdAllChars) - 1;
static constexpr int kWaitMs = 1100;

static int g_failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "FAIL: " << msg << " [" << __FILE__ << ":" << __LINE__ << "]" << std::endl; \
        ++g_failures; \
    } else { \
        std::cout << "PASS: " << msg << std::endl; \
    } \
} while (0)

static void V1_AutoInitAndGenerate()
{
    uint8_t buf1[64], buf2[64];
    cdf::RandDeinit();
    CHECK(cdf::GetRand(buf1, 64) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V1: auto-init GetRand#1");
    CHECK(cdf::GetRand(buf2, 64) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V1: auto-init GetRand#2");
    CHECK(std::memcmp(buf1, buf2, 64) != 0, "V1: two outputs differ");
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
        CHECK(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag);
        uint8_t buf[32];
        tag = std::string("V2: GetRand ") + drbg;
        CHECK(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag);
        cdf::RandHealthStatus st;
        CHECK(cdf::GetRandHealthStatus(st) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK,
              std::string("V2: healthStatus ") + drbg);
        CHECK(st.isHealthy, std::string("V2: isHealthy ") + drbg);
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
        CHECK(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag);
        uint8_t buf[32];
        CHECK(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag + " generate");
    }
    cdf::RandDeinit();
}

static void V4_PredictionResistance()
{
    cdf::RandDeinit();
    cdf::RandConfig cfg;
    cfg.predictionResistance = true;
    CHECK(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V4: init");
    bool different = false;
    for (int retry = 0; retry < 5 && !different; ++retry) {
        uint8_t a[64], b[64];
        if (cdf::GetRand(a, 64) != cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            continue;
        }
        if (cdf::GetRand(b, 64) != cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            continue;
        }
        different = (std::memcmp(a, b, 64) != 0);
    }
    CHECK(different, "V4: predictionResistance produces different output");
    cdf::RandDeinit();
}

static void V5_HealthCheck()
{
    cdf::RandDeinit();
    cdf::RandConfig cfg;
    cfg.healthCheckInterval = 1000;
    CHECK(cdf::RandInit(cfg) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V5: init");
    uint8_t buf[32];
    CHECK(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V5: first GetRand");
    std::this_thread::sleep_for(std::chrono::milliseconds(kWaitMs));
    CHECK(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK,
          "V5: second GetRand triggers health check");
    cdf::RandHealthStatus st;
    CHECK(cdf::GetRandHealthStatus(st) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V5: healthStatus");
    CHECK(st.isHealthy, "V5: isHealthy");
    CHECK(st.entropySufficient, "V5: entropySufficient");
    CHECK(st.errorCount == 0U, "V5: errorCount=0");
    cdf::RandDeinit();
}

static void V6_ConcurrentStress()
{
    cdf::RandDeinit();
    CHECK(cdf::RandInit() == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V6: init");
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
    CHECK(errors.load() == 0, "V6: concurrent stress no errors");
    cdf::RandDeinit();
}

static void V7_DeinitReinitCycle()
{
    for (int cycle = 0; cycle < 5; ++cycle) {
        cdf::RandDeinit();
        std::string tag = "V7: reinit cycle " + std::to_string(cycle);
        CHECK(cdf::RandInit() == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag);
        uint8_t buf[32];
        CHECK(cdf::GetRand(buf, 32) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag + " GetRand");
        CHECK(cdf::GetSecurePwd(buf, 8) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag + " SecurePwd");
    }
    cdf::RandDeinit();
}

static void V8_SecurePwdQuality()
{
    cdf::RandDeinit();
    CHECK(cdf::RandInit() == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, "V8: init");
    for (uint32_t len = 8; len <= 32; ++len) {
        std::vector<uint8_t> pwd(len);
        std::string tag = "V8: securePwd len=" + std::to_string(len);
        CHECK(cdf::GetSecurePwd(pwd.data(), len) == cdf::CcsecCryptErrorCode::CCSEC_CRYPT_OK, tag);
        for (uint32_t i = 0; i < len; ++i) {
            bool valid = false;
            for (size_t j = 0; j < kPwdAllCharsLen; ++j) {
                if (pwd[i] == static_cast<uint8_t>(kPwdAllChars[j])) {
                    valid = true;
                    break;
                }
            }
            CHECK(valid, tag + " char[" + std::to_string(i) + "]");
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
