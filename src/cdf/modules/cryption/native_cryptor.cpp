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

#include "cdf/modules/cryption/native_cryptor.h"

#include <string>
#include <utility>
#include <vector>

#include "cdf/base/ccsec_logger.h"
#include "cdf/modules/cryption/native_cryptor_engine.h"

namespace cdf {

std::mutex NativeCryptor::gMutex;

CcsecCipherSuite GetCipherSuite(const CryptoSymAlg &alg)
{
    switch (alg) {
        case CryptoSymAlg::AES128_GCM:
            return CcsecCipherSuite::CCSEC_AES_GCM_128;
        case CryptoSymAlg::AES256_GCM:
            return CcsecCipherSuite::CCSEC_AES_GCM_256;
        case CryptoSymAlg::SM4_CTR:
            return CcsecCipherSuite::CCSEC_SM4_CTR;
        case CryptoSymAlg::AES128_CCM:
            return CcsecCipherSuite::CCSEC_AES_CCM_128;
        case CryptoSymAlg::CHACHA20_POLY1305:
            return CcsecCipherSuite::CCSEC_CHACHA20_POLY1305;
        default:
            return CcsecCipherSuite::CCSEC_UNSPECIFIED;
    }
}

std::pair<CryptionRC, std::vector<std::byte>> NativeCryptor::Encrypt(const CryptoSymAlg &alg,
                                                                     std::vector<std::byte> &plaintext,
                                                                     std::vector<std::byte> &key)
{
    std::unique_lock<std::mutex> guard(gMutex);
    CryptoEngine *engine = CryptoEngine::Instance();
    if (engine == nullptr) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Failed to get instance");
        return {CryptionRC::ERROR, {}};
    }
    CcsecCipherSuite cipherSuite = GetCipherSuite(alg);
    if (cipherSuite == CcsecCipherSuite::CCSEC_UNSPECIFIED) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Invalid param alg");
        return {CryptionRC::INVALID_PARAM, {}};
    }
    engine->GetCryptoConfig().SetMCipherSuite(cipherSuite);

    if (plaintext.empty() || (plaintext.size() >= PLAINTEXT_MAX_LENGTH)) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Invalid param plaintext");
        return {CryptionRC::INVALID_PARAM, {}};
    }
    if (key.empty()) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Invalid param key");
        return {CryptionRC::INVALID_PARAM, {}};
    }

    const uint8_t *cryptoKey = reinterpret_cast<const uint8_t *>(key.data());
    const uint8_t *text = reinterpret_cast<const uint8_t *>(plaintext.data());

    uint32_t cipherTextLen = EstimatedCipherLen(plaintext.size());
    uint8_t cipherText[cipherTextLen];
    int32_t ret = KeyEncrypt(cryptoKey, key.size(), text, plaintext.size(), cipherText, &cipherTextLen);
    if (ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Failed to encrypt, error code is:" << ret);
        return {CryptionRC::ERROR, {}};
    }

    std::vector<std::byte> vec(cipherTextLen);
    // 使用 memcpy_s 函数将 cipherText 数组中的数据复制到 vec 容器中
    if (memcpy_s(vec.data(), vec.size(), cipherText, cipherTextLen) != 0) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Failed to memcpy_s");
        return {CryptionRC::ERROR, {}};
    }
    return {CryptionRC::OK, vec};
}

std::pair<CryptionRC, std::vector<std::byte>> NativeCryptor::Decrypt(const CryptoSymAlg &alg,
                                                                     std::vector<std::byte> &ciphertext,
                                                                     std::vector<std::byte> &key)
{
    std::unique_lock<std::mutex> guard(gMutex);
    CryptoEngine *engine = CryptoEngine::Instance();
    if (engine == nullptr) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Failed to get instance");
        return {CryptionRC::ERROR, {}};
    }
    CcsecCipherSuite cipherSuite = GetCipherSuite(alg);
    if (cipherSuite == CcsecCipherSuite::CCSEC_UNSPECIFIED) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Invalid param alg");
        return {CryptionRC::INVALID_PARAM, {}};
    }
    engine->GetCryptoConfig().SetMCipherSuite(cipherSuite);
    if (ciphertext.empty() || ciphertext.size() >= CIPHERTEXT_MAX_LENGTH) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Invalid param ciphertext");
        return {CryptionRC::INVALID_PARAM, {}};
    }

    if (key.empty()) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Invalid param key");
        return {CryptionRC::INVALID_PARAM, {}};
    }
    const uint8_t *cryptoKey = reinterpret_cast<const uint8_t *>(key.data());
    const uint8_t *text = reinterpret_cast<const uint8_t *>(ciphertext.data());
    uint32_t plainTextLen = EstimatedCipherLen(ciphertext.size());
    uint8_t plainText[plainTextLen];
    int32_t ret = KeyDecrypt(cryptoKey, key.size(), text, ciphertext.size(), plainText, &plainTextLen);
    if (ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Failed to decrypt, error code is:" << ret);
        (void)memset_s(plainText, plainTextLen, 0, plainTextLen);
        return {CryptionRC::ERROR, {}};
    }

    std::vector<std::byte> vec(plainTextLen);
    if (memcpy_s(vec.data(), vec.size(), plainText, plainTextLen) != 0) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Failed to memcpy_s");
        (void)memset_s(plainText, plainTextLen, 0, plainTextLen);
        return {CryptionRC::ERROR, {}};
    }
    (void)memset_s(plainText, plainTextLen, 0, plainTextLen);
    return {CryptionRC::OK, vec};
}

int32_t Pbkdf2Hmac(const std::vector<uint8_t> &key, const Pbkdf2ConfigStruct &pbkdf2ConfigStruct,
                   std::vector<uint8_t> &outBase64)
{
    CryptoEngine *engine = CryptoEngine::Instance();
    return engine->Pbkdf2Hmac(key, pbkdf2ConfigStruct, outBase64);
}

int32_t GetPbkdf2Config(const std::vector<uint8_t> &base64Code, Pbkdf2ConfigStruct &pbkdf2ConfigStruct)
{
    CryptoEngine *engine = CryptoEngine::Instance();
    return engine->GetPbkdf2Config(base64Code, pbkdf2ConfigStruct);
}
} // namespace cdf
