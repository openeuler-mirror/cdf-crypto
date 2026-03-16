// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
// Confidential Data defensive Framework is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#pragma once

#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "cdf/modules/cryption/define.h"
#include "cdf/modules/cryption/native_cryptor_def.h"

namespace cdf {

const uint32_t PLAINTEXT_MAX_LENGTH = 1024 * 1024;      // 加密的明文最大长度
const uint32_t CIPHERTEXT_MAX_LENGTH = 2 * 1024 * 1024; // 解密的密文最大长度

class NativeCryptor {
public:
    /**
     * @brief Encrypt plaintext to base64 ciphertext with given symmetric
     * algorithm.
     * @param[in] alg
     * @param[in] plaintext
     * @param[in] key
     * @return std::pair<CryptionRC, std::vector<std::byte>> {CryptionRC::OK, ciphertext}
     * on success, {CryptionRC::[OTHER_ERROR_CODE], empty} on failure.
     */
    std::pair<CryptionRC, std::vector<std::byte>> Encrypt(const CryptoSymAlg &alg, std::vector<std::byte> &plaintext,
                                                          std::vector<std::byte> &key);

    /**
     * @brief Decrypt base64 ciphertext to plaintext with given symmetric
     * algorithm.
     * @param[in] alg
     * @param[in] plaintext
     * @param[in] key
     * @return std::pair<CryptionRC, std::vector<std::byte>> {CryptionRC::OK,
     * ciphertext} on success, {CryptionRC::[OTHER_ERROR_CODE], empty} on
     * failure.
     */
    std::pair<CryptionRC, std::vector<std::byte>> Decrypt(const CryptoSymAlg &alg, std::vector<std::byte> &ciphertext,
                                                          std::vector<std::byte> &key);
private:
    static std::mutex gMutex;
};

enum class CcsecCipherSuite {
    CCSEC_AES_GCM_128 = 0,
    CCSEC_AES_GCM_256 = 1,
    CCSEC_AES_CCM_128 = 2,
    CCSEC_CHACHA20_POLY1305 = 3,
    CCSEC_SM4_CTR = 4,
    CCSEC_UNSPECIFIED
};

/**
 * Pbkdf2Hmac PBKDF2对密钥进行派生
 * default algId is CCSEC_CRYPT_MAC_HMAC_SHA256;
 * default iterationTimes is 100000.
 * @param key [IN] Password, input by the user. password length is any length, including 0.
 * @param pbkdf2ConfigStruct [IN] PBKDF2所用的参数 取值如下
 * 1、ccsecCryptMacAlgId [IN] HMAC algorithm ID (Only the HMAC algorithm ID is supported, including
 * CCSEC_CRYPT_MAC_HMAC_SHA256, CCSEC_CRYPT_MAC_HMAC_SHA384, CCSEC_CRYPT_MAC_HMAC_SHA512,
 * CCSEC_CRYPT_MAC_HMAC_SM3) 默认CCSEC_CRYPT_MAC_HMAC_SHA256
 * 2、iterationTimes [IN] Iteration times. The value can be a positive integer that is not 0. The value
 * can be 1000 in special performance scenarios. The default value is 100000,
 * 10000000 is recommended in scenarios where performance is insensitive or
 * security requirements are high. The value range is [1000, 20000000]. 默认100000
 * 3、outLen [IN] Length of the derived key. The value range is [32, 128]. 默认64
 * 4、salt [IN] Salt value, input by the user. length [16, 64].
 * @param outBase64 [OUT]  输出结果，已base64转码 且包含算法id 迭代次数 盐值信息 密钥派生长度信息.
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
int32_t Pbkdf2Hmac(const std::vector<uint8_t> &key, const Pbkdf2ConfigStruct &pbkdf2ConfigStruct,
                   std::vector<uint8_t> &outBase64);
/**
 * GetPbkdf2Config 将Pbkdf2Hmac接口生成的结果解析，将算法id、盐值、迭代次数、密钥派生长度通过Pbkdf2ConfigStruct返回
 * @param base64Code [IN] Pbkdf2Hmac接口生成的结果
 * @param pbkdf2ConfigStruct [OUT] 所用的配置信息
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
int32_t GetPbkdf2Config(const std::vector<uint8_t> &base64Code, Pbkdf2ConfigStruct &pbkdf2ConfigStruct);

} // namespace cdf
