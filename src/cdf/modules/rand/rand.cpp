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
#include "openssl/rand.h"
#include "cdf/base/ccsec_logger.h"
#include "cdf/modules/cryption/native_cryptor_engine.h"
#include "cdf/modules/rand/rand.h"

namespace cdf {

namespace {
const uint32_t MIN_RAND_LEN = 1;
const uint32_t MAX_RAND_LEN = 65536;
const uint32_t MIN_SECURE_PWD_LEN = 8;
const uint32_t MAX_SECURE_PWD_LEN = 32;
const int32_t RAND_BUF_SIZE = 128;
const int32_t MAX_RETRY_TIMES = 10;
const int NUM_BYTES = 8;

const char PWD_ALL_CHARS[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "`~!@#$%^&*()-_=+\\|[]{};:'\" ,<.>/?";
constexpr size_t PWD_ALL_CHARS_LEN = sizeof(PWD_ALL_CHARS) - 1;
static std::atomic<bool> g_randInitialized(false);

enum class CharType : uint8_t {
    DIGIT = 0,   // 数字类型
    LOWER = 1,   // 小写字母
    UPPER = 2,   // 大写字母
    SPECIAL = 3, // 特殊字符
};
} // namespace

CcsecCryptErrorCode RandInit()
{
    CCSEC_LOG_INFO("|RandInit|START|||");
    // 检查是否已经初始化
    if (g_randInitialized.load()) {
        CCSEC_LOG_INFO("|RandInit|END|returnS||Already initialized");
        return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
    }
    g_randInitialized.store(true);  // 为了保持接口与源代码一致
    CCSEC_LOG_INFO("|RandInit|END|returnS||RandInit success");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

CcsecCryptErrorCode GetRand(uint8_t *out, uint32_t length)
{
    CCSEC_LOG_INFO("|GetRand|START|||");
    // 检查随机数生成器是否已初始化
    if (!g_randInitialized.load()) {
        CCSEC_LOG_ERROR("|GetRand|END|returnF||Random generator not initialized");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }

    if (out == nullptr) {
        CCSEC_LOG_ERROR("|GetRand|END|returnF||out is nullptr.");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (length < MIN_RAND_LEN || length > MAX_RAND_LEN) {
        CCSEC_LOG_ERROR("|GetRand|END|returnF||length is invalid.");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }

    // 获得len长度的随机数序列
    int ret = RAND_priv_bytes(out, length);
    if (ret != OpenSSLRC::OK) {
        CCSEC_LOG_ERROR("|GetRand|END|returnF||RAND_priv_bytes failed, error code is:" << ret);
        return CCSEC_CRYPT_ERROR;
    }
    CCSEC_LOG_INFO("|GetRand|END|returnS||GetRand success");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

void RandDeinit(void)
{
    CCSEC_LOG_INFO("|RandDeinit|START|||");
    g_randInitialized.store(false); // 为了保持接口与源代码一致
    CCSEC_LOG_INFO("|RandDeinit|END|returnS||RandDeinit success");
}

bool HasMultipleCharTypes(const uint8_t *pwd, uint32_t length)
{
    uint8_t types = 0;
    for (uint32_t i = 0; i < length; ++i) {
        const char c = pwd[i];
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

CcsecCryptErrorCode GetSecurePwd(uint8_t *pwdBuff, const uint32_t pwdLength)
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
    if (RandInit() != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
        CCSEC_LOG_ERROR("|GetSecurePwd|END|returnF||failed to init rand");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }
    // 生成增强随机数（原始长度的8倍）
    // 满足nist-sp800-90A, Appendix A.5.3 随机数标准
    const uint32_t enhancedRandLen = pwdLength * NUM_8;
    std::unique_ptr<uint8_t[]> enhancedRand = std::make_unique<uint8_t[]>(enhancedRandLen);
    uint8_t retry = 0;
    while (retry++ < MAX_RETRY_TIMES) {
        // 生成增强随机数
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
            RandDeinit();
            (void)memset_s(enhancedRand.get(), enhancedRandLen, 0, enhancedRandLen);
            CCSEC_LOG_INFO("|GetSecurePwd|END|returnS||get secure password successfully");
            return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
        }
    }
    // 安全擦除
    (void)memset_s(pwdBuff, pwdLength, 0, pwdLength);
    (void)memset_s(enhancedRand.get(), enhancedRandLen, 0, enhancedRandLen);
    RandDeinit();
    CCSEC_LOG_ERROR("|GetSecurePwd|END|returnF||failed to get secure password, max retries exceeded");
    return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
}

} // namespace cdf