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

#include <atomic>
#include <chrono>
#include <cctype>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include "openssl/core.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/objects.h"
#include "openssl/provider.h"
#include "openssl/rand.h"
#include "securec.h"
#include "cdf/base/common_define.h"
#include "cdf/base/ccsec_logger.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/rand/rand.h"

namespace cdf {

namespace {
const uint32_t MIN_RAND_LEN = 1;
const uint32_t MAX_RAND_LEN = 65536;
const uint32_t MIN_SECURE_PWD_LEN = 8;
const uint32_t MAX_SECURE_PWD_LEN = 32;
const uint32_t MIN_SEC_STRENGTH = 112;
const uint32_t MAX_SEC_STRENGTH = 256;
const uint32_t MAX_GET_RAND_ATTEMPTS = 1000;

const char PWD_ALL_CHARS[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "`~!@#$%^&*()-_=+\\|[]{};:'\" ,<.>/?";
constexpr size_t PWD_ALL_CHARS_LEN = sizeof(PWD_ALL_CHARS) - 1;

// 全局状态变量
static std::atomic<bool> g_initialized(false);
static std::mutex g_initMutex;
static std::atomic<uint32_t> g_errorCount(0);
static std::atomic<uint32_t> g_healthCheckInterval(0);
static std::atomic<int64_t> g_lastHealthCheckMs(0);
#ifdef CDF_RAND_TESTING
static std::atomic<uint32_t> g_healthCheckCount(0);
#endif

// EVP_RAND 私有实例 — 与 OpenSSL 全局 RAND_* 状态完全隔离
static EVP_RAND_CTX *g_pRandCtx = nullptr;
static EVP_RAND_CTX *g_pParentCtx = nullptr;
static EVP_RAND *g_pDrbg = nullptr;
static EVP_RAND *g_pParent = nullptr;
static std::mutex g_randMutex;

// 当前生效配置（用于 predictionResistance 等运行期参数）
static RandConfig g_activeConfig;

// 已加载的 Provider 引用，在 RandDeinit 中统一释放。
// Provider 通过 OSSL_PROVIDER_load(nullptr, ...) 注册到 OpenSSL default libctx；
// 后续 EVP_RAND_fetch(nullptr, ...) 通过该 libctx 间接使用这些 Provider。
static OSSL_PROVIDER *g_customProvider = nullptr;
static OSSL_PROVIDER *g_fipsProvider = nullptr;
static OSSL_PROVIDER *g_defaultProvider = nullptr;
static std::mutex g_providerMutex;

enum class CharType : uint8_t {
    DIGIT = 0,   // 数字类型
    LOWER = 1,   // 小写字母
    UPPER = 2,   // 大写字母
    SPECIAL = 3, // 特殊字符
};

// 内部辅助函数：通过日志记录错误
void RecordError([[maybe_unused]] const std::string &errorMsg)
{
    g_errorCount.fetch_add(1);
    CCSEC_LOG_ERROR("|RandModule|||" << errorMsg);
}

int64_t NowMs()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

// 内部辅助函数：验证配置参数
bool ValidateConfig(const RandConfig &config)
{
    if (config.drbgType != "CTR-DRBG" && config.drbgType != "HASH-DRBG" && config.drbgType != "HMAC-DRBG") {
        RecordError("Invalid DRBG type: " + config.drbgType);
        return false;
    }
    if (config.seedSource != "SEED-SRC" && config.seedSource != "OS" &&
        config.seedSource != "HARDWARE" && config.seedSource != "CUSTOM") {
        RecordError("Invalid seed source: " + config.seedSource);
        return false;
    }
    if (config.securityStrength < MIN_SEC_STRENGTH || config.securityStrength > MAX_SEC_STRENGTH) {
        RecordError("Invalid security strength: " + std::to_string(config.securityStrength));
        return false;
    }
    if (config.drbgType == "CTR-DRBG" && config.securityStrength != 128 &&
        config.securityStrength != 192 && config.securityStrength != 256) {
        RecordError("Invalid CTR-DRBG security strength: " + std::to_string(config.securityStrength));
        return false;
    }
    return true;
}

std::string BuildProviderPropq(const std::string &providerName)
{
    return std::string("provider=") + providerName;
}

struct RandFetchSpec {
    std::string parentName;
    // propq 是 OpenSSL property query，用于约束 EVP_RAND_fetch 的实现来源或属性。
    std::string parentPropq;
    std::string drbgPropq;
};

struct DrbgParamStorage {
    std::string cipher;
    std::string digest;
    std::string mac;
    std::string properties;
};

std::string FormatFetchTarget(const std::string &name, const std::string &propq)
{
    if (propq.empty()) {
        return name;
    }
    return name + " [" + propq + "]";
}

RandFetchSpec BuildFetchSpec(const RandConfig &config)
{
    RandFetchSpec spec;
    spec.drbgPropq = config.fipsMode ? "fips=yes" : "";

    if (config.seedSource == "CUSTOM") {
        spec.parentName = "SEED-SRC";
        spec.parentPropq = BuildProviderPropq(config.customSeedProvider);
        return spec;
    }

    if (config.seedSource == "HARDWARE" || config.fipsMode) {
        spec.parentName = "JITTER";
        spec.parentPropq = config.fipsMode ? "fips=yes" : "";
        return spec;
    }

    spec.parentName = "SEED-SRC";
    return spec;
}

bool FetchRandAvailable(const std::string &name, const std::string &propq)
{
    EVP_RAND *rand = EVP_RAND_fetch(nullptr, name.c_str(), propq.empty() ? nullptr : propq.c_str());
    if (rand == nullptr) {
        return false;
    }
    EVP_RAND_free(rand);
    return true;
}

bool LoadDefaultProvider()
{
    if (g_defaultProvider != nullptr) {
        return true;
    }
    g_defaultProvider = OSSL_PROVIDER_load(nullptr, "default");
    if (g_defaultProvider == nullptr) {
        RecordError("Default provider not available");
        return false;
    }
    return true;
}

bool LoadFipsProvider()
{
    if (!LoadDefaultProvider()) {
        return false;
    }
    if (g_fipsProvider != nullptr) {
        return true;
    }
    g_fipsProvider = OSSL_PROVIDER_load(nullptr, "fips");
    if (g_fipsProvider == nullptr) {
        RecordError("FIPS provider not available");
        return false;
    }
    return true;
}

// 内部辅助函数：按配置加载需要显式持有生命周期的 Provider
bool PrepareProviders(const RandConfig &config)
{
    if (config.fipsMode && !LoadFipsProvider()) {
        return false;
    }

    if (config.seedSource != "CUSTOM") {
        return LoadDefaultProvider();
    }

    if (config.customSeedProvider.empty()) {
        RecordError("Custom seed provider name not specified");
        return false;
    }
    OSSL_PROVIDER *customProvider = OSSL_PROVIDER_load(nullptr, config.customSeedProvider.c_str());
    if (customProvider == nullptr) {
        RecordError("Failed to load custom seed provider: " + config.customSeedProvider);
        return false;
    }
    g_customProvider = customProvider;
    return true;
}

// 内部辅助函数：验证配置得到的 parent RAND 是否可 fetch
bool ValidateParentRandAvailable(const RandConfig &config)
{
    const RandFetchSpec fetchSpec = BuildFetchSpec(config);
    if (FetchRandAvailable(fetchSpec.parentName, fetchSpec.parentPropq)) {
        return true;
    }

    RecordError("Seed source unavailable: " +
                FormatFetchTarget(fetchSpec.parentName, fetchSpec.parentPropq));
    return false;
}

// 内部辅助函数：构建 DRBG 参数 (strength→cipher/digest 映射)
bool BuildDrbgParams(const RandConfig &config, const std::string &propq,
                     DrbgParamStorage &storage, OSSL_PARAM *params, size_t &idx)
{
    idx = 0;
    if (config.drbgType == "CTR-DRBG") {
        if (config.securityStrength <= 128) {
            storage.cipher = "AES-128-CTR";
        } else if (config.securityStrength <= 192) {
            storage.cipher = "AES-192-CTR";
        } else {
            storage.cipher = "AES-256-CTR";
        }
        params[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_DRBG_PARAM_CIPHER, storage.cipher.data(), 0);
    } else {
        if (config.securityStrength <= 112) {
            storage.digest = "SHA-224";
        } else if (config.securityStrength <= 128) {
            storage.digest = "SHA-256";
        } else if (config.securityStrength <= 192) {
            storage.digest = "SHA-384";
        } else {
            storage.digest = "SHA-512";
        }
        params[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_DRBG_PARAM_DIGEST, storage.digest.data(), 0);
        if (config.drbgType == "HMAC-DRBG") {
            storage.mac = "HMAC";
            params[idx++] = OSSL_PARAM_construct_utf8_string(
                OSSL_DRBG_PARAM_MAC, storage.mac.data(), 0);
        }
    }
    storage.properties = propq;
    if (!storage.properties.empty()) {
        params[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_DRBG_PARAM_PROPERTIES, storage.properties.data(), 0);
    }
    params[idx] = OSSL_PARAM_construct_end();
    return true;
}

// 内部辅助函数：构建 EVP_RAND 链并实例化
bool BuildRandChain(const RandConfig &config)
{
    const RandFetchSpec fetchSpec = BuildFetchSpec(config);

    // Step 1: 获取 parent 熵源
    g_pParent = EVP_RAND_fetch(nullptr, fetchSpec.parentName.c_str(),
                               fetchSpec.parentPropq.empty() ? nullptr : fetchSpec.parentPropq.c_str());
    if (g_pParent == nullptr) {
        RecordError("EVP_RAND_fetch failed for parent RAND: " +
                    FormatFetchTarget(fetchSpec.parentName, fetchSpec.parentPropq));
        return false;
    }

    // Step 2: 构建 parent 上下文（EVP_RAND_CTX_new 的 parent 参数是 EVP_RAND_CTX*）
    g_pParentCtx = EVP_RAND_CTX_new(g_pParent, nullptr);
    if (g_pParentCtx == nullptr) {
        RecordError("EVP_RAND_CTX_new for parent RAND failed: " +
                    FormatFetchTarget(fetchSpec.parentName, fetchSpec.parentPropq));
        EVP_RAND_free(g_pParent);
        g_pParent = nullptr;
        return false;
    }

    unsigned int strength = static_cast<unsigned int>(config.securityStrength);
    if (EVP_RAND_instantiate(g_pParentCtx, strength, 0, nullptr, 0, nullptr) != 1) {
        RecordError("EVP_RAND_instantiate failed for parent RAND: " +
                    FormatFetchTarget(fetchSpec.parentName, fetchSpec.parentPropq));
        EVP_RAND_CTX_free(g_pParentCtx);
        g_pParentCtx = nullptr;
        EVP_RAND_free(g_pParent);
        g_pParent = nullptr;
        return false;
    }

    // Step 3: 构建 DRBG 算法参数
    OSSL_PARAM params[8];
    DrbgParamStorage paramStorage;
    size_t paramIdx = 0;
    if (!BuildDrbgParams(config, fetchSpec.drbgPropq, paramStorage, params, paramIdx)) {
        EVP_RAND_CTX_free(g_pParentCtx);
        g_pParentCtx = nullptr;
        EVP_RAND_free(g_pParent);
        g_pParent = nullptr;
        return false;
    }

    // Step 4: 获取 DRBG 算法
    g_pDrbg = EVP_RAND_fetch(nullptr, config.drbgType.c_str(),
                             fetchSpec.drbgPropq.empty() ? nullptr : fetchSpec.drbgPropq.c_str());
    if (g_pDrbg == nullptr) {
        RecordError("EVP_RAND_fetch failed for DRBG: " +
                    FormatFetchTarget(config.drbgType, fetchSpec.drbgPropq));
        EVP_RAND_CTX_free(g_pParentCtx);
        g_pParentCtx = nullptr;
        EVP_RAND_free(g_pParent);
        g_pParent = nullptr;
        return false;
    }

    // Step 5: 创建 DRBG 上下文（parentCtx 作为熵源）
    g_pRandCtx = EVP_RAND_CTX_new(g_pDrbg, g_pParentCtx);
    if (g_pRandCtx == nullptr) {
        RecordError("EVP_RAND_CTX_new for DRBG failed");
        EVP_RAND_CTX_free(g_pParentCtx);
        g_pParentCtx = nullptr;
        EVP_RAND_free(g_pDrbg);
        g_pDrbg = nullptr;
        EVP_RAND_free(g_pParent);
        g_pParent = nullptr;
        return false;
    }

    // Step 6: OS 熵源补充采集。
    // seedSource="OS" 不改变 parent RAND 选择；这里显式触发 OpenSSL 从 OS 熵源补充采集。
    if (config.seedSource == "OS") {
        if (RAND_poll() != 1) {
            RecordError("RAND_poll failed for OS seed source");
        }
    }

    // Step 7: 实例化 DRBG
    int prFlag = config.predictionResistance ? 1 : 0;
    if (EVP_RAND_instantiate(g_pRandCtx, strength, prFlag, nullptr, 0, params) != 1) {
        RecordError("EVP_RAND_instantiate failed");
        EVP_RAND_CTX_free(g_pRandCtx);
        g_pRandCtx = nullptr;
        EVP_RAND_CTX_free(g_pParentCtx);
        g_pParentCtx = nullptr;
        EVP_RAND_free(g_pDrbg);
        g_pDrbg = nullptr;
        EVP_RAND_free(g_pParent);
        g_pParent = nullptr;
        return false;
    }

    return true;
}

// 内部辅助函数：清理 EVP_RAND 资源
void CleanupRandResources()
{
    if (g_pRandCtx != nullptr) {
        EVP_RAND_CTX_free(g_pRandCtx);
        g_pRandCtx = nullptr;
    }
    if (g_pParentCtx != nullptr) {
        EVP_RAND_CTX_free(g_pParentCtx);
        g_pParentCtx = nullptr;
    }
    if (g_pDrbg != nullptr) {
        EVP_RAND_free(g_pDrbg);
        g_pDrbg = nullptr;
    }
    if (g_pParent != nullptr) {
        EVP_RAND_free(g_pParent);
        g_pParent = nullptr;
    }
}

// 内部辅助函数：清理 Provider 资源
void CleanupProviders()
{
    if (g_customProvider != nullptr) {
        OSSL_PROVIDER_unload(g_customProvider);
        g_customProvider = nullptr;
    }
    if (g_fipsProvider != nullptr) {
        OSSL_PROVIDER_unload(g_fipsProvider);
        g_fipsProvider = nullptr;
    }
    if (g_defaultProvider != nullptr) {
        OSSL_PROVIDER_unload(g_defaultProvider);
        g_defaultProvider = nullptr;
    }
}

} // namespace

CcsecCryptErrorCode RandInit(const RandConfig &config)
{
    CCSEC_LOG_INFO("|RandInit|START|||");

    if (g_initialized.load()) {
        CCSEC_LOG_INFO("|RandInit|END|returnS||Already initialized");
        return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
    }

    std::lock_guard<std::mutex> initLock(g_initMutex);

    if (g_initialized.load()) {
        CCSEC_LOG_INFO("|RandInit|END|returnS||Already initialized (double check)");
        return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
    }

    if (!ValidateConfig(config)) {
        CCSEC_LOG_ERROR("|RandInit|END|returnF||Config validation failed");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }

    // 加载需要显式持有生命周期的 Provider。必须在 EVP_RAND_fetch 前完成。
    {
        std::lock_guard<std::mutex> providerLock(g_providerMutex);
        if (!PrepareProviders(config)) {
            CleanupProviders();
            CCSEC_LOG_ERROR("|RandInit|END|returnF||PrepareProviders failed");
            return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
        }
    }

    if (!ValidateParentRandAvailable(config)) {
        CleanupProviders();
        CCSEC_LOG_ERROR("|RandInit|END|returnF||ValidateParentRandAvailable failed");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }

    // 构建 EVP_RAND 链并实例化
    if (!BuildRandChain(config)) {
        CleanupProviders();
        CleanupRandResources();
        CCSEC_LOG_ERROR("|RandInit|END|returnF||BuildRandChain failed");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }

    // 保存配置并标记初始化完成
    g_errorCount.store(0);
    g_healthCheckInterval.store(config.healthCheckInterval);
    g_lastHealthCheckMs.store(NowMs());
#ifdef CDF_RAND_TESTING
    g_healthCheckCount.store(0);
#endif
    g_activeConfig = config;
    g_initialized.store(true);

    CCSEC_LOG_INFO("|RandInit|END|returnS||RandInit success");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

CcsecCryptErrorCode EnsureRandReady()
{
    if (g_initialized.load()) {
        return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
    }
    CCSEC_LOG_INFO("|GetRand|||Auto initializing with default config");
    CcsecCryptErrorCode initRet = RandInit(RandConfig{});
    if (initRet != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
        CCSEC_LOG_ERROR("|GetRand|END|returnF||Auto initialization failed");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

CcsecCryptErrorCode GetRand(uint8_t *randBuff, const uint32_t randDataLength)
{
    CCSEC_LOG_INFO("|GetRand|START|||");

    if (randBuff == nullptr) {
        CCSEC_LOG_ERROR("|GetRand|END|returnF||randBuff is nullptr");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (randDataLength < MIN_RAND_LEN || randDataLength > MAX_RAND_LEN) {
        CCSEC_LOG_ERROR("|GetRand|END|returnF||randDataLength is invalid");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }

    for (uint32_t attempt = 0; attempt < MAX_GET_RAND_ATTEMPTS; ++attempt) {
        if (EnsureRandReady() != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            continue;
        }

        std::lock_guard<std::mutex> initLock(g_initMutex);
        {
            std::lock_guard<std::mutex> randLock(g_randMutex);
            if (!g_initialized.load() || g_pRandCtx == nullptr) {
                continue;
            }

            uint32_t checkInterval = g_healthCheckInterval.load();
            if (checkInterval > 0) {
                const int64_t nowMs = NowMs();
                const int64_t lastCheckMs = g_lastHealthCheckMs.load();
                if (nowMs - lastCheckMs >= static_cast<int64_t>(checkInterval)) {
                    int state = EVP_RAND_get_state(g_pRandCtx);
#ifdef CDF_RAND_TESTING
                    g_healthCheckCount.fetch_add(1);
#endif
                    if (state != EVP_RAND_STATE_READY) {
                        RecordError("EVP_RAND_get_state not ready, state=" + std::to_string(state));
                        CCSEC_LOG_ERROR("|GetRand|END|returnF||Periodic health check failed");
                        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
                    }
                    g_lastHealthCheckMs.store(nowMs);
                }
            }

            unsigned int strength = static_cast<unsigned int>(g_activeConfig.securityStrength);
            int prFlag = g_activeConfig.predictionResistance ? 1 : 0;
            int ret = EVP_RAND_generate(g_pRandCtx, randBuff,
                                        static_cast<size_t>(randDataLength),
                                        strength, prFlag, nullptr, 0);
            if (ret != 1) {
                RecordError("EVP_RAND_generate failed");
                CCSEC_LOG_ERROR("|GetRand|END|returnF||EVP_RAND_generate failed");
                return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
            }

            CCSEC_LOG_INFO("|GetRand|END|returnS||GetRand success");
            return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
        }
    }

    CCSEC_LOG_ERROR("|GetRand|END|returnF||Rand context unavailable");
    return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
}

CcsecCryptErrorCode GetRandHealthStatus(RandHealthStatus &status)
{
    CCSEC_LOG_INFO("|GetRandHealthStatus|START|||");

    if (!g_initialized.load()) {
        status.isHealthy = false;
        status.entropySufficient = false;
        status.errorCount = g_errorCount.load();
        CCSEC_LOG_INFO("|GetRandHealthStatus|END|returnS||Not initialized");
        return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
    }

    {
        std::lock_guard<std::mutex> randLock(g_randMutex);
        if (g_initialized.load() && g_pRandCtx != nullptr) {
            int state = EVP_RAND_get_state(g_pRandCtx);
            status.isHealthy = (state == EVP_RAND_STATE_READY);
            status.entropySufficient = (RAND_status() == 1);
        } else {
            status.isHealthy = false;
            status.entropySufficient = false;
        }
    }

    status.errorCount = g_errorCount.load();

    CCSEC_LOG_INFO("|GetRandHealthStatus|END|returnS||Health status retrieved");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

#ifdef CDF_RAND_TESTING
uint32_t GetRandHealthCheckCountForTest()
{
    return g_healthCheckCount.load();
}
#endif

void RandDeinit()
{
    CCSEC_LOG_INFO("|RandDeinit|START|||");

    std::lock_guard<std::mutex> initLock(g_initMutex);

    {
        std::lock_guard<std::mutex> randLock(g_randMutex);
        CleanupRandResources();
    }

    {
        std::lock_guard<std::mutex> providerLock(g_providerMutex);
        CleanupProviders();
    }

    g_initialized.store(false);
    g_errorCount.store(0);
    g_healthCheckInterval.store(0);
    g_lastHealthCheckMs.store(0);
#ifdef CDF_RAND_TESTING
    g_healthCheckCount.store(0);
#endif
    g_activeConfig = RandConfig{};

    CCSEC_LOG_INFO("|RandDeinit|END|returnS||RandDeinit success");
}

bool HasMultipleCharTypes(const uint8_t *pwd, uint32_t length)
{
    uint8_t types = 0;
    for (uint32_t i = 0; i < length; ++i) {
        const unsigned char c = pwd[i];
        if (isdigit(c)) {
            types |= 1 << static_cast<uint8_t>(CharType::DIGIT);
        } else if (islower(c)) {
            types |= 1 << static_cast<uint8_t>(CharType::LOWER);
        } else if (isupper(c)) {
            types |= 1 << static_cast<uint8_t>(CharType::UPPER);
        } else { // 特殊字符
            types |= 1 << static_cast<uint8_t>(CharType::SPECIAL);
        }
    }
    // 检查至少包含两种类型
    // 例如：只有1种类型时, types：0b0001，types - 1：0b0000, types & (types-1) 为 0
    // 有2种类型时, types：0b0011, types - 1：0b0010, types & (types-1) 不为 0
    // 大于2种类型时, types & (types-1)均不为0
    return (types & (types - 1)) != 0;
}

CcsecCryptErrorCode GetSecurePwd(uint8_t *pwdBuff, const uint32_t pwdLength, const uint32_t retryTimes)
{
    CCSEC_LOG_INFO("|GetSecurePwd|START|||get secure password");
    if (pwdBuff == nullptr) {
        CCSEC_LOG_ERROR("|GetSecurePwd|END|returnF||pwdBuff is nullptr");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (pwdLength < MIN_SECURE_PWD_LEN || pwdLength > MAX_SECURE_PWD_LEN) {
        CCSEC_LOG_ERROR("|GetSecurePwd|END|returnF||pwdLength is invalid: "<< pwdLength
                        << ", must in range [" << MIN_SECURE_PWD_LEN << ", " << MAX_SECURE_PWD_LEN << "].");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (retryTimes == 0) {
        CCSEC_LOG_ERROR("|GetSecurePwd|END|returnF||retryTimes is 0");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }

    // 生成增强随机数（原始长度的8倍）
    // 满足nist-sp800-90A, Appendix A.5.3 随机数标准
    const uint32_t enhancedRandLen = pwdLength * NUM_8;
    std::unique_ptr<uint8_t[]> enhancedRand = std::make_unique<uint8_t[]>(enhancedRandLen);
    uint32_t retry = 0;
    while (retry++ < retryTimes) {
        // 生成增强随机数（GetRand 内部会自动初始化）
        if (GetRand(enhancedRand.get(), enhancedRandLen) != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            CCSEC_LOG_WARN("|GetSecurePwd|||retry: " << retry << "|failed to get rand");
            continue;
        }
        // 每次处理8字节生成1个密码字符
        for (uint32_t pwdIdx = 0; pwdIdx < pwdLength; ++pwdIdx) {
            // 计算当前块起始位置
            const uint32_t blockStart = pwdIdx * NUM_8;
            // 将8字节转换为64位整数
            uint64_t randValue = 0;
            for (int i = 0; i < NUM_8; ++i) {
                randValue = (randValue << NUM_8) | enhancedRand[blockStart + i];
            }
            pwdBuff[pwdIdx] = PWD_ALL_CHARS[randValue % PWD_ALL_CHARS_LEN];
        }
        // 检查至少包含两种类型
        if (HasMultipleCharTypes(pwdBuff, pwdLength)) {
            (void)memset_s(enhancedRand.get(), enhancedRandLen, 0, enhancedRandLen);
            CCSEC_LOG_INFO("|GetSecurePwd|END|returnS||get secure password successfully");
            return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
        }
    }
    // 安全擦除
    (void)memset_s(pwdBuff, pwdLength, 0, pwdLength);
    (void)memset_s(enhancedRand.get(), enhancedRandLen, 0, enhancedRandLen);
    CCSEC_LOG_ERROR("|GetSecurePwd|END|returnF||failed to get secure password, max retries exceeded");
    return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
}

} // namespace cdf
