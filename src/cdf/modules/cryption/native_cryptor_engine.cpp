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

#include <cstdint>
#include <set>

#include "ossl_wrappers.h"
#include "cdf/modules/rand/rand.h"
#include "cdf/utils/base64.h"
#include "cdf/base/ccsec_logger.h"
#include "cdf/modules/cryption/native_cryptor_engine.h"


namespace cdf {
#define CHECK_RET_FALSE(_condition, _msg, _ret)                    \
    do {                                                           \
        if (_condition) {                                          \
            CCSEC_LOG_ERROR("|check msg|END|returnF||" << (_msg)); \
            return (_ret);                                         \
        }                                                          \
    } while (0)

#define OPENSSL_CHECK_RET_FALSE(_ret, _msg)                                                                        \
    do {                                                                                                           \
        if ((_ret) != OpenSSLRC::OK) {                                                                             \
            CCSEC_LOG_ERROR("|check msg|END|returnF||" << (_msg));                                                 \
            return CCSEC_CRYPT_ERROR;                                                                              \
        }                                                                                                          \
    } while (0)

size_t base64_encode_len(size_t input_len)
{
    return (input_len + 2) / 3 * 4 + 1; // 每 3 字节输入 → 4 字节输出，向上取整, 2为3的最大余数
}

size_t base64_decode_len(size_t base64_len)
{
    // 注意：实际解码长度可能因填充（=）而更小，此处返回最大值
    return (base64_len / 4) * 3 + 3; // 每 4 字节 Base64 最多解码为 3 字节二进制，预留少量冗余
}

std::unique_ptr<CryptoEngine> CryptoEngine::CryptoEngineInstance = nullptr;

std::mutex CryptoEngine::cryptoEngineMutex;

namespace {
const uint32_t ALG_LEN_128 = 128;
const uint32_t ALG_LEN_256 = 256;
const uint32_t MULTIPLIER_FACTOR = 8;
} // namespace

static inline const char* convertCipherSuiteId(CcsecCipherSuite cipherSuite)
{
    switch (cipherSuite) {
        case CcsecCipherSuite::CCSEC_AES_GCM_128:
            return "aes-128-gcm";
        case CcsecCipherSuite::CCSEC_AES_GCM_256:
            return "aes-256-gcm";
        case CcsecCipherSuite::CCSEC_AES_CCM_128:
            return "aes-128-ccm";
        case CcsecCipherSuite::CCSEC_CHACHA20_POLY1305:
            return "chacha20-poly1305";
        case CcsecCipherSuite::CCSEC_SM4_CTR:
            return "sm4-ctr";
        default:
            return nullptr;  // 返回空指针表示无效算法
    }
}

static inline const char* ConvertOpenSSLAlgId(CcsecCryptMacAlgId cryptMacAlgId)
{
    switch (cryptMacAlgId) {
        case CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA256:
            return "sha2-256";
        case CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA384:
            return "sha2-384";
        case CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA512:
            return "sha2-512";
        case CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SM3:
            return "sm3";
        default:
            return nullptr;  // 返回空指针表示无效算法
    }
}

uint32_t GetAlgLen(CcsecCipherSuite mCipherSuite)
{
    switch (mCipherSuite) {
        case CcsecCipherSuite::CCSEC_AES_GCM_128:
        case CcsecCipherSuite::CCSEC_AES_CCM_128:
        case CcsecCipherSuite::CCSEC_SM4_CTR:
            return ALG_LEN_128;
        case CcsecCipherSuite::CCSEC_AES_GCM_256:
        case CcsecCipherSuite::CCSEC_CHACHA20_POLY1305:
            return ALG_LEN_256;
        default:
            return 0;
    }
}

int32_t CryptoEngine::Encrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *plainText,
                              const uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    if (cryptoKey == nullptr || cipherText == nullptr || plainText == nullptr || plainTextLen == 0 ||
        cryptoKeyLen == 0) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Invalid params.");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    CcsecCipherSuite mCipherSuite = cryptoConfig.GetCipherSuite();
    uint32_t algLen = GetAlgLen(mCipherSuite);
    // 检查 cryptoKeyLen * MULTIPLIER_FACTOR 是否溢出
    if (cryptoKeyLen > UINT32_MAX / MULTIPLIER_FACTOR) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Invalid cryptoKeyLen, multiplication would cause overflow.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_CRYPT_AES_ERR_KEYLEN;
    }
    CHECK_RET_FALSE((cryptoKeyLen * MULTIPLIER_FACTOR != algLen), "Invalid keyLen",
                    CcsecCryptErrorCode::CCSEC_OPENSSL_CRYPT_AES_ERR_KEYLEN);
    CHECK_RET_FALSE((algLen == 0), "Invalid alg", CcsecCryptErrorCode::CCSEC_OPENSSL_CRYPT_EAL_ERR_ALGID);
    return OpensslEncrypt(cryptoKey, cryptoKeyLen, plainText, plainTextLen, cipherText, cipherTextLen);
}

// todo: 函数入参为字符串时，使用指针+长度的格式，偏离C++风格，统一整改，使用C++的风格
int32_t CryptoEngine::OpensslCcmEncrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                                        const uint8_t *plainText, const uint32_t plainTextLen, uint8_t *cipherText,
                                        uint32_t *cipherTextLen)
{
    // 生成IVLength的随机IV向量（GetRand 内部会自动初始化）
    int32_t ret = GetRand(cipherText + cryptoConfig.GetIVOffset(), cryptoConfig.GetIVLength());
    CHECK_RET_FALSE(ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK, "Generate IV failed",
                    CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    // 生成AADLength的随机AAD向量
    ret = GetRand(cipherText + cryptoConfig.GetAADOffset(), cryptoConfig.GetAADLength());
    CHECK_RET_FALSE(ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK, "Generate AAD failed",
                    CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);

    size_t ivLength = cryptoConfig.GetIVLength();
    const uint8_t* iv = cipherText + cryptoConfig.GetIVOffset();
    std::vector<uint8_t> ivData(iv, iv + ivLength);
    // 获取加解密上下文
    auto ctx = ossl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|OpensslCcmEncrypt|END|returnF||UniqueCipherCtx is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }
    // 获取加密算法
    CcsecCipherSuite mCipherSuite = cryptoConfig.GetCipherSuite();
    const auto cipher = ossl::FetchEvpCipher(convertCipherSuiteId(mCipherSuite));
    if (cipher == nullptr) {
        CCSEC_LOG_ERROR("|OpensslCcmEncrypt|END|returnF||FetchEvpCipher cipher is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }
    // 初始化加密算法
    ret = EVP_EncryptInit_ex(ctx.get(), cipher.get(), nullptr, nullptr, nullptr);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|Failed to EVP_EncryptInit_ex");

    int out_length = 0;
    // 设置IV长度
    ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN, cryptoConfig.GetIVLength(), nullptr);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|EVP_CIPHER_CTX_ctrl set ivlen fail");
    // 设置TAG长度
    ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, cryptoConfig.GetTagLength(), NULL);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|EVP_CIPHER_CTX_ctrl set tag fail");
    // 设置Key、IV数据
    ret = EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, cryptoKey, ivData.data());
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|EVP_EncryptInit_ex set iv fail");
    // 设置明文长度
    ret = EVP_EncryptUpdate(ctx.get(), nullptr, &out_length, nullptr, plainTextLen);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|EVP_EncryptUpdate plainTextLen fail");
    // 设置AAD
    ret = EVP_EncryptUpdate(ctx.get(), nullptr, &out_length,
                            cipherText + cryptoConfig.GetAADOffset(), cryptoConfig.GetAADLength());
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|EVP_EncryptUpdate AAD fail");

    int cipher_length = 0;
    ret = EVP_EncryptUpdate(ctx.get(), cipherText + cryptoConfig.GetCipherOffset(), &out_length,
                            plainText, plainTextLen);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|Failed to EVP_EncryptUpdate");
    cipher_length += out_length;

    ret = EVP_EncryptFinal_ex(ctx.get(),
                              cipherText + cryptoConfig.GetCipherOffset() + cipher_length, &out_length);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|Failed to EVP_EncryptFinal_ex");
    // 计算最后密文长度
    *cipherTextLen = EstimatedCipherLen(plainTextLen);

    // 获取TAG
    ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_GET_TAG, cryptoConfig.GetTagLength(),
                              cipherText + cryptoConfig.GetTagOffset());
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmEncrypt|END|returnF|Failed to SetTag");
    if (static_cast<uint32_t>(EVP_CIPHER_CTX_get_tag_length(ctx.get())) != cryptoConfig.GetTagLength()) {
        CCSEC_LOG_ERROR("OpensslCcmEncrypt|END|returnF|UnMatch TagLength");
        return false;
    }

    CCSEC_LOG_INFO("|OpensslCcmEncrypt|END|returnS||CryptoEngine encrypt success.");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

int32_t CryptoEngine::OpensslEncrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                                     const uint8_t *plainText, const uint32_t plainTextLen, uint8_t *cipherText,
                                     uint32_t *cipherTextLen)
{
    // 当CCM时使用单独的方式加解密
    if (cryptoConfig.GetCipherSuite() ==  CcsecCipherSuite::CCSEC_AES_CCM_128) {
        return OpensslCcmEncrypt(cryptoKey, cryptoKeyLen, plainText,
                                   plainTextLen, cipherText, cipherTextLen);
    }
    // 生成IVLength的随机IV向量（GetRand 内部会自动初始化）
    int32_t ret = GetRand(cipherText + cryptoConfig.GetIVOffset(), cryptoConfig.GetIVLength());
    CHECK_RET_FALSE(ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK, "Generate IV failed",
                    CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    // 生成AADLength的随机AAD向量
    ret = GetRand(cipherText + cryptoConfig.GetAADOffset(), cryptoConfig.GetAADLength());
    CHECK_RET_FALSE(ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK, "Generate AAD failed",
                    CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);

    auto ctx = ossl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|OpensslEncrypt|END|returnF||UniqueCipherCtx is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }

    CcsecCipherSuite mCipherSuite = cryptoConfig.GetCipherSuite();
    const auto cipher = ossl::FetchEvpCipher(convertCipherSuiteId(mCipherSuite));
    if (cipher == nullptr) {
        CCSEC_LOG_ERROR("|OpensslEncrypt|END|returnF||FetchEvpCipher cipher is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }
    if ((cryptoConfig.GetIVLength() != static_cast<uint32_t>(EVP_CIPHER_iv_length(cipher.get()))) ||
        (cryptoKeyLen != static_cast<uint32_t>(EVP_CIPHER_key_length(cipher.get())))) {
        CCSEC_LOG_ERROR("|OpensslEncrypt|END|returnF||iv or key length unmatch");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }
    // 初始化上下文
    ret = EVP_EncryptInit_ex(ctx.get(), cipher.get(), nullptr, cryptoKey,
                             cipherText + cryptoConfig.GetIVOffset());
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslEncrypt|END|returnF|Failed to EVP_EncryptInit_ex");
    int out_length = 0;
    // 除了SM4场景外，设置AAD
    if (mCipherSuite != CcsecCipherSuite::CCSEC_SM4_CTR) {
        ret = EVP_EncryptUpdate(ctx.get(), nullptr, &out_length,
                                cipherText + cryptoConfig.GetAADOffset(), cryptoConfig.GetAADLength());
        OPENSSL_CHECK_RET_FALSE(ret, "OpensslEncrypt|END|returnF|Failed to SetAAD");
    }
    ret = EVP_EncryptUpdate(ctx.get(), cipherText + cryptoConfig.GetCipherOffset(), &out_length,
                            plainText, plainTextLen);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslEncrypt|END|returnF|Failed to EVP_EncryptUpdate");

    ret = EVP_EncryptFinal_ex(ctx.get(), nullptr, &out_length);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslEncrypt|END|returnF|Failed to EVP_EncryptFinal_ex");
    // 计算最后密文长度
    *cipherTextLen = EstimatedCipherLen(plainTextLen);

    // 除了SM4场景，设置TAG
    if (mCipherSuite != CcsecCipherSuite::CCSEC_SM4_CTR) {
        // 获取TAG
        ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, cryptoConfig.GetTagLength(),
                                  cipherText + cryptoConfig.GetTagOffset());
        OPENSSL_CHECK_RET_FALSE(ret, "OpensslEncrypt|END|returnF|Failed to SetTag");
    }
    CCSEC_LOG_INFO("|OpensslEncrypt|END|returnS||CryptoEngine encrypt success.");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

int32_t CryptoEngine::Decrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *cipherText,
                              const uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    if (cryptoKey == nullptr || cipherText == nullptr || cipherTextLen == 0 || plainText == nullptr ||
        plainTextLen == nullptr || cryptoKeyLen == 0) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Invalid params.");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (cipherTextLen <= cryptoConfig.GetCipherOffset()) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Invalid ciphertext length.");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    CcsecCipherSuite mCipherSuite = cryptoConfig.GetCipherSuite();
    uint32_t algLen = GetAlgLen(mCipherSuite);
    // 检查 cryptoKeyLen * MULTIPLIER_FACTOR 是否溢出
    if (cryptoKeyLen > UINT32_MAX / MULTIPLIER_FACTOR) {
        CCSEC_LOG_ERROR("|Decrypt|END|returnF||Invalid cryptoKeyLen, multiplication would cause overflow.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_CRYPT_AES_ERR_KEYLEN;
    }
    CHECK_RET_FALSE((cryptoKeyLen * MULTIPLIER_FACTOR != algLen), "Invalid keyLen",
                    CcsecCryptErrorCode::CCSEC_OPENSSL_CRYPT_AES_ERR_KEYLEN);
    CHECK_RET_FALSE((algLen == 0), "Invalid alg", CcsecCryptErrorCode::CCSEC_OPENSSL_CRYPT_EAL_ERR_ALGID);
    return OpensslDecrypt(cryptoKey, cryptoKeyLen, cipherText, cipherTextLen, plainText, plainTextLen);
}

int32_t CryptoEngine::OpensslCcmDecrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                                        const uint8_t *cipherText, const uint32_t cipherTextLen,
                                        uint8_t *plainText, uint32_t *plainTextLen)
{
    // 将iv、key存放入单独的vector中，防止只传入数组指针时数据读取错误
    size_t ivLength = cryptoConfig.GetIVLength();
    const uint8_t* iv = cipherText + cryptoConfig.GetIVOffset();
    std::vector<uint8_t> ivData(iv, iv + ivLength);
    std::vector<uint8_t> keyData(cryptoKey, cryptoKey + cryptoKeyLen);
    // tag长度
    uint32_t tagLen = cryptoConfig.GetTagLength();
    // 密文长度
    auto cipherLen = cipherTextLen - cryptoConfig.GetCipherOffset();
    // 保存密文的tag信息用于解密完的比较
    uint8_t tagBuffer[tagLen] = {0};
    CHECK_RET_FALSE((memcpy_s(tagBuffer, tagLen, cipherText + cryptoConfig.GetTagOffset(), tagLen) != EOK),
                    "Failed to copy tag to buffer", CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    // 获取加解密上下文
    auto ctx = ossl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|OpensslCcmDecrypt|END|returnF||UniqueCipherCtx is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }
    // 获取加密算法
    CcsecCipherSuite mCipherSuite = cryptoConfig.GetCipherSuite();
    const auto cipher = ossl::FetchEvpCipher(convertCipherSuiteId(mCipherSuite));
    if (cipher == nullptr) {
        CCSEC_LOG_ERROR("|OpensslCcmDecrypt|END|returnF||FetchEvpCipher is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }

    // 初始化加密算法
    auto ret = EVP_DecryptInit_ex(ctx.get(), cipher.get(), nullptr, nullptr, nullptr);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmDecrypt|END|returnF|CCM Init fail");
    // 设置IV长度
    int out_length = 0;
    ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN,
                              cryptoConfig.GetIVLength(), nullptr);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmDecrypt|END|returnF|CCM set IVLEN fail");
    // 设置TAG长度及值
    ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG,
                              cryptoConfig.GetTagLength(), tagBuffer);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmDecrypt|END|returnF|CCM set TAG fail");
    // 设置Key、IV数据
    ret = EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, keyData.data(),
                             ivData.data());
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmDecrypt|END|returnF|Failed to EVP_EncryptInit_ex");

    // 设置密文长度
    ret = EVP_DecryptUpdate(ctx.get(), nullptr, &out_length, nullptr, cipherLen);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmDecrypt|END|returnF|CCM set cipherLen fail");
    // 设置AAD
    ret = EVP_DecryptUpdate(ctx.get(), nullptr, &out_length,
                            cipherText + cryptoConfig.GetAADOffset(), cryptoConfig.GetAADLength());
    if (static_cast<uint32_t>(out_length) != cryptoConfig.GetAADLength()) {
        CCSEC_LOG_ERROR("|OpensslCcmDecrypt|END|returnF||Unmatch AAD length");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }

    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmDecrypt|END|returnF|Failed to SetAAD");
    // 根据明文及上下文进行解密
    ret = EVP_DecryptUpdate(ctx.get(), plainText, &out_length,
                            cipherText + cryptoConfig.GetCipherOffset(), cipherLen);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslCcmDecrypt|END|returnF|Failed to EVP_EncryptUpdate");
    *plainTextLen = EstimatedPlainLen(cipherTextLen);
    CCSEC_LOG_INFO("|OpensslCcmDecrypt|END|returnS||CryptoEngine decrypt success.");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

int32_t CryptoEngine::OpensslDecrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                                     const uint8_t *cipherText, const uint32_t cipherTextLen,
                                     uint8_t *plainText, uint32_t *plainTextLen)
{
    // 当CCM时使用单独的方式加解密
    if (cryptoConfig.GetCipherSuite() ==  CcsecCipherSuite::CCSEC_AES_CCM_128) {
        return OpensslCcmDecrypt(cryptoKey, cryptoKeyLen, cipherText,
                                   cipherTextLen, plainText, plainTextLen);
    }
    uint32_t tagLen = cryptoConfig.GetTagLength();
    // 保存密文的tag信息用于解密完的比较
    uint8_t tagBuffer[tagLen] = {0};

    CHECK_RET_FALSE((memcpy_s(tagBuffer, tagLen, cipherText + cryptoConfig.GetTagOffset(), tagLen) != EOK),
                    "Failed to copy tag to buffer", CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    auto ctx = ossl::UniqueCipherCtx(EVP_CIPHER_CTX_new());
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|OpensslDecrypt|END|returnF||UniqueCipherCtx is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }
    CcsecCipherSuite mCipherSuite = cryptoConfig.GetCipherSuite();
    const auto cipher = ossl::FetchEvpCipher(convertCipherSuiteId(mCipherSuite));
    if (cipher == nullptr) {
        CCSEC_LOG_ERROR("|OpensslDecrypt|END|returnF||FetchEvpCipher is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }
    size_t ivLength = cryptoConfig.GetIVLength();
    const uint8_t* iv = cipherText + cryptoConfig.GetIVOffset();
    std::vector<uint8_t> ivData(iv, iv + ivLength);

    // 初始化上下文
    auto ret = EVP_DecryptInit_ex(ctx.get(), cipher.get(), nullptr, cryptoKey,
                                  ivData.data());
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslDecrypt|END|returnF|Failed to EVP_EncryptInit_ex");

    int out_length = 0;
    // 除了SM4模式，设置AAD
    if (mCipherSuite != CcsecCipherSuite::CCSEC_SM4_CTR) {
        ret = EVP_DecryptUpdate(ctx.get(), nullptr, &out_length,
                                cipherText + cryptoConfig.GetAADOffset(), cryptoConfig.GetAADLength());
        if (static_cast<uint32_t>(out_length) != cryptoConfig.GetAADLength()) {
            CCSEC_LOG_ERROR("|OpensslDecrypt|END|returnF||Unmatch AAD length");
            return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
        }
        OPENSSL_CHECK_RET_FALSE(ret, "OpensslDecrypt|END|returnF|Failed to SetAAD");
    }
    auto cipherLen = cipherTextLen - cryptoConfig.GetCipherOffset();
    ret = EVP_DecryptUpdate(ctx.get(), plainText, &out_length,
                            cipherText + cryptoConfig.GetCipherOffset(), cipherLen);
    OPENSSL_CHECK_RET_FALSE(ret, "OpensslDecrypt|END|returnF|Failed to EVP_EncryptUpdate");
    *plainTextLen = EstimatedPlainLen(cipherTextLen);
    // 除了SM4场景，设置TAG
    if (mCipherSuite != CcsecCipherSuite::CCSEC_SM4_CTR) {
        // 设置TAG
        ret = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, tagLen, (void*)tagBuffer);
        OPENSSL_CHECK_RET_FALSE(ret, "OpensslDecrypt|END|returnF|Failed to SetTag");
        ret = EVP_DecryptFinal_ex(ctx.get(), nullptr, &out_length);
        if (ret <= 0) {
            CCSEC_LOG_ERROR("|OpensslDecrypt|END|returnF||Tag different, decrypt failed.");
            return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
        }
    }

    CCSEC_LOG_INFO("|OpensslDecrypt|END|returnS||CryptoEngine decrypt success.");
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

uint32_t CryptoEngine::EstimatedCipherLen(uint32_t plainTextLen) const
{
    auto cipherLen = static_cast<uint32_t>(cryptoConfig.GetCipherOffset());
    // 使用uint64_t来避免在计算过程中溢出
    uint64_t tempCipherLen = static_cast<uint64_t>(plainTextLen) + static_cast<uint64_t>(cipherLen);
    // 检查是否溢出
    if (tempCipherLen > UINT32_MAX) {
        CCSEC_LOG_ERROR("|CryptoEngine EstimatedCipherLen|END|returnF||estimated cipherlen is larger than UINT32_MAX");
        return 0;
    }
    cipherLen += plainTextLen;
    return cipherLen;
}

uint32_t CryptoEngine::EstimatedPlainLen(uint32_t cipherTextLen) const
{
    if (cipherTextLen <= cryptoConfig.GetCipherOffset()) {
        return 0;
    }
    return cipherTextLen - cryptoConfig.GetCipherOffset();
}


int32_t CryptoEngine::InitCrypto(CcsecCipherSuite suite)
{
    std::unique_lock<std::mutex> guard(cryptoEngineMutex);
    CryptoEngine *engine = CryptoEngine::Instance();
    if (engine->cryptoConfig.GetCipherSuite() != CcsecCipherSuite::CCSEC_UNSPECIFIED) {
        CCSEC_LOG_INFO("|get CipherSuite|END|returnS||Crypto has been initialized, CcsecCipherSuite is:" <<
                       static_cast<int32_t>(cryptoConfig.GetCipherSuite()));
        return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
    }
    switch (suite) {
        case CcsecCipherSuite::CCSEC_AES_GCM_128:
        case CcsecCipherSuite::CCSEC_AES_GCM_256:
        case CcsecCipherSuite::CCSEC_AES_CCM_128:
        case CcsecCipherSuite::CCSEC_CHACHA20_POLY1305:
        case CcsecCipherSuite::CCSEC_SM4_CTR:
            engine->cryptoConfig.SetMCipherSuite(suite);
            return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
        default:
            CCSEC_LOG_ERROR("|get CipherSuite|END|returnF||Invalid CipherSuite:" << static_cast<int32_t>(suite));
            return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
}

const std::set<CcsecCryptMacAlgId> ValidPbkdf2Alg = []() {
    std::set<CcsecCryptMacAlgId> enumSet;
    enumSet.insert(CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA256);
    enumSet.insert(CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA384);
    enumSet.insert(CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA512);
    enumSet.insert(CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SM3);
    return enumSet;
}();

CcsecCryptErrorCode ValidatePbkdf2Config(const Pbkdf2ConfigStruct &pbkdf2ConfigStruct)
{
    if (ValidPbkdf2Alg.find(pbkdf2ConfigStruct.ccsecCryptMacAlgId) == ValidPbkdf2Alg.end()) {
        CCSEC_LOG_ERROR("|Pbkdf2Hmac ValidatePbkdf2Config|END|returnF||invalid algId.");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (pbkdf2ConfigStruct.salt.size() < PBKDF2_SALT_LEN_MIN || pbkdf2ConfigStruct.salt.size() > PBKDF2_SALT_LEN_MAX) {
        CCSEC_LOG_ERROR(
            "|Pbkdf2Hmac ValidatePbkdf2Config|END|returnF||saltLen value is:"
            << pbkdf2ConfigStruct.salt.size() << ", which is out of range ["
            << PBKDF2_SALT_LEN_MIN << "-" << PBKDF2_SALT_LEN_MAX << "]");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (pbkdf2ConfigStruct.iterationTimes < PBKDF2_ITERATION_TIMES_MIN ||
        pbkdf2ConfigStruct.iterationTimes > PBKDF2_ITERATION_TIMES_MAX) {
        CCSEC_LOG_ERROR(
            "|Pbkdf2Hmac ValidatePbkdf2Config|END|returnF||iterationTimes value is:"
            << pbkdf2ConfigStruct.iterationTimes << ", which is out of range ["
            << PBKDF2_ITERATION_TIMES_MIN << "-" << PBKDF2_ITERATION_TIMES_MAX << "]");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    if (pbkdf2ConfigStruct.outLen < PBKDF2_OUT_LEN_MIN || pbkdf2ConfigStruct.outLen > PBKDF2_OUT_LEN_MAX) {
        CCSEC_LOG_ERROR(
            "|Pbkdf2Hmac ValidatePbkdf2Config|END|returnF||outLen value is:"
            << pbkdf2ConfigStruct.outLen << ", which is out of range ["
            << PBKDF2_OUT_LEN_MIN << "-" << PBKDF2_OUT_LEN_MAX << "]");
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    return CcsecCryptErrorCode::CCSEC_CRYPT_OK;
}

int32_t CryptoEngine::Pbkdf2Hmac(const std::vector<uint8_t> &key, const Pbkdf2ConfigStruct &pbkdf2ConfigStruct,
                                 std::vector<uint8_t> &outBase64)
{
    if (ValidatePbkdf2Config(pbkdf2ConfigStruct) != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
        return CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID;
    }
    auto algId = pbkdf2ConfigStruct.ccsecCryptMacAlgId;
    auto iterationTimes = pbkdf2ConfigStruct.iterationTimes;
    auto outLen = pbkdf2ConfigStruct.outLen;
    uint8_t outTmp[PBKDF2_OUT_OFFSET + outLen + pbkdf2ConfigStruct.salt.size()] = {0};
    // 存储算法id
    outTmp[0] = static_cast<uint8_t>(algId);

    // 存储迭代次数：将32位无符号整数iterationTimes分解为4个字节，按大端序（Big-Endian）存储到输出缓冲区
    // 大端序表示高位字节在前（outTmp[1]是最高字节，outTmp[4]是最低字节）
    outTmp[1] = (iterationTimes >> 24) & 0xFF;  // 取最高字节[1]（右移24位后，保留低8位）
    outTmp[2] = (iterationTimes >> 16) & 0xFF;  // 取次高字节[2]（右移16位后，保留低8位）
    outTmp[3] = (iterationTimes >> 8) & 0xFF;   // 取次低字节[3]（右移8位后，保留低8位）
    outTmp[4] = iterationTimes & 0xFF;          // 取最低字节[4]（直接保留低8位）

    // 存储输出长度：将16位无符号整数outLen分解为2个字节，按大端序（Big-Endian）存储到输出缓冲区
    // 大端序表示高位字节在前（outTmp[5]是高字节，outTmp[6]是低字节）
    outTmp[5] = (outLen >> 8) & 0xFF;   // 取高字节[5]（右移8位后，保留低8位）
    outTmp[6] = outLen & 0xFF;          // 取低字节[6]（直接保留低8位）
    CCSEC_LOG_DEBUG("|CryptoEngine Pbkdf2DeriveKey|RUNNING|||algId:" << static_cast<int32_t>(algId)
        << ", saltLen:" << pbkdf2ConfigStruct.salt.size() << ", iterationTimes:"
        << iterationTimes << ", outLen:" << outLen);
    const ossl::UniqueMd alg = ossl::FetchEvpMd(ConvertOpenSSLAlgId(algId));
    if (alg == nullptr) {
        CCSEC_LOG_ERROR("|Pbkdf2Hmac|END|returnF||FetchEvpMd alg is null.");
        return CcsecCryptErrorCode::CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL;
    }
    int ret = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(key.data()),
                                key.size(), pbkdf2ConfigStruct.salt.data(),
                                pbkdf2ConfigStruct.salt.size(), iterationTimes, alg.get(),
                                outLen, outTmp + PBKDF2_OUT_OFFSET);
    OPENSSL_CHECK_RET_FALSE(ret, "|Pbkdf2Hmac|END|returnF||CRYPT_EAL_Pbkdf2");

    if (memcpy_s(outTmp + PBKDF2_OUT_OFFSET + outLen, pbkdf2ConfigStruct.salt.size(), pbkdf2ConfigStruct.salt.data(),
                 pbkdf2ConfigStruct.salt.size()) != EOK) {
        CCSEC_LOG_ERROR("|Pbkdf2Hmac|END|returnF||memcpy_s error");
        return CcsecCryptErrorCode::CCSEC_CRYPT_ERROR;
    }

    uint32_t encodeBufLen = base64_encode_len(PBKDF2_OUT_OFFSET + outLen + pbkdf2ConfigStruct.salt.size());
    outBase64.resize(encodeBufLen);

    std::vector<std::byte> encodedData = Base64Encode(reinterpret_cast<const char*>(outTmp),
                                                      PBKDF2_OUT_OFFSET + outLen + pbkdf2ConfigStruct.salt.size());
    outBase64.clear();
    outBase64.insert(
        outBase64.end(),
        reinterpret_cast<unsigned char*>(encodedData.data()),
        reinterpret_cast<unsigned char*>(encodedData.data() + encodedData.size())
    );

    CCSEC_LOG_DEBUG("|CryptoEngine Pbkdf2Hmac|END|returnS||Pbkdf2Hmac success");
    return static_cast<int32_t>(CcsecCryptErrorCode::CCSEC_CRYPT_OK);
}

int32_t CryptoEngine::GetPbkdf2Config(const std::vector<uint8_t> &base64Code, Pbkdf2ConfigStruct &pbkdf2ConfigStruct)
{
    CCSEC_LOG_DEBUG("|CryptoEngine GetPbkdf2Config|START|||");
    auto srcLen = base64Code.size();
    // Base64的长度，将每3个字节的二进制数据转换为4个字节的Base64字符（+2 是为了处理可能的余数（1或2字节））
    uint32_t minSrcLen = (PBKDF2_OUT_OFFSET + PBKDF2_OUT_LEN_MIN + PBKDF2_SALT_LEN_MIN + 2) / 3 * 4;
    if (srcLen < minSrcLen) {
        CCSEC_LOG_ERROR("|GetPbkdf2Config|END|returnF||base64Code len is "
                        << srcLen << ", which is less than minSrcLen: " << minSrcLen);
        return static_cast<int32_t>(CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
    }
    uint32_t decodeBufLen = base64_decode_len(srcLen);
    uint8_t decodeBuf[decodeBufLen];

    // 将 base64Code 转换为 std::string_view
    std::string_view encodedString(reinterpret_cast<const char*>(base64Code.data()), base64Code.size());

    // 解码 Base64 数据
    std::vector<unsigned char> decodedData = Base64Decode(encodedString);
    if (decodedData.size() > decodeBufLen) {
        CCSEC_LOG_ERROR("|GetPbkdf2Config|END|returnF||decodedData error");
        return static_cast<int32_t>(CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    }
    // 将解码后的数据复制到 decodeBuf 中
    std::copy(decodedData.begin(), decodedData.end(), decodeBuf);
    decodeBufLen = decodedData.size();

    // 算法id
    // 从解码缓冲区中读取第2到第5个字节，组合成一个32位无符号整数，表示PBKDF2算法的迭代次数
    // 每个字节通过左移操作和按位或操作合并到iterationTimes中
    pbkdf2ConfigStruct.ccsecCryptMacAlgId = static_cast<CcsecCryptMacAlgId>(decodeBuf[0]);
    uint32_t iterationTimes = 0;
    iterationTimes |= static_cast<uint32_t>(decodeBuf[1]) << 24; // decodeBuf[1] 左移24位（最高字节）
    iterationTimes |= static_cast<uint32_t>(decodeBuf[2]) << 16; // decodeBuf[2] 左移16位
    iterationTimes |= static_cast<uint32_t>(decodeBuf[3]) << 8; // decodeBuf[3] 左移8位
    iterationTimes |= static_cast<uint32_t>(decodeBuf[4]); // decodeBuf[4] 不左移（最低字节）
    // 迭代次数
    // 从解码缓冲区中读取第6和第7个字节，组合成一个16位无符号整数，表示PBKDF2算法的输出长度
    pbkdf2ConfigStruct.iterationTimes = iterationTimes;
    uint32_t outLen = 0;
    outLen |= static_cast<uint32_t>(decodeBuf[5]) << 8; // decodeBuf[5] 左移8位（高字节）
    outLen |= static_cast<uint32_t>(decodeBuf[6]); // decodeBuf[6] 不左移（低字节）
    // outLen
    pbkdf2ConfigStruct.outLen = outLen;
    uint32_t saltLen = decodeBufLen - outLen - PBKDF2_OUT_OFFSET;

    // salt
    pbkdf2ConfigStruct.salt.resize(saltLen);
    if (memcpy_s(pbkdf2ConfigStruct.salt.data(), saltLen, decodeBuf + PBKDF2_OUT_OFFSET + outLen, saltLen) != EOK) {
        CCSEC_LOG_ERROR("|GetPbkdf2Config|END|returnF||memcpy_s error");
        return static_cast<int32_t>(CcsecCryptErrorCode::CCSEC_CRYPT_ERROR);
    }
    CCSEC_LOG_DEBUG("|CryptoEngine GetPbkdf2Config|END|returnS||GetPbkdf2Config success");
    return static_cast<int32_t>(CcsecCryptErrorCode::CCSEC_CRYPT_OK);
}

int32_t InitCrypto(CcsecCipherSuite cipherSuite)
{
    CryptoEngine *engine = CryptoEngine::Instance();
    return engine->InitCrypto(cipherSuite);
}

int32_t KeyEncrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *plainText,
                   const uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen)
{
    // 设置加密套件
    CryptoEngine *engine = CryptoEngine::Instance();
    CcsecCipherSuite suite = engine->GetCryptoConfig().GetCipherSuite();
    if (suite == CcsecCipherSuite::CCSEC_UNSPECIFIED) {
        CCSEC_LOG_INFO("|check CcsecCipherSuite||||CcsecCipherSuite not set use defaulf suite CCSEC_AES_GCM_256 and "
                       "cryptoKeyLen should be 32.");
        auto ret = engine->InitCrypto(CcsecCipherSuite::CCSEC_AES_GCM_256);
        if (ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            return ret;
        }
    }
    return engine->Encrypt(cryptoKey, cryptoKeyLen, plainText, plainTextLen, cipherText, cipherTextLen);
}

int32_t KeyDecrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *cipherText,
                   const uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    CryptoEngine *engine = CryptoEngine::Instance();
    CcsecCipherSuite suite = engine->GetCryptoConfig().GetCipherSuite();
    if (suite == CcsecCipherSuite::CCSEC_UNSPECIFIED) {
        CCSEC_LOG_INFO("|check CcsecCipherSuite||||CcsecCipherSuite not set use defaulf suite CCSEC_AES_GCM_256 and "
                       "cryptoKeyLen should be 32.");
        auto ret = engine->InitCrypto(CcsecCipherSuite::CCSEC_AES_GCM_256);
        if (ret != CcsecCryptErrorCode::CCSEC_CRYPT_OK) {
            return ret;
        }
    }
    return engine->Decrypt(cryptoKey, cryptoKeyLen, cipherText, cipherTextLen, plainText, plainTextLen);
}

uint32_t EstimatedCipherLen(uint32_t plainTextLen)
{
    CryptoEngine *engine = CryptoEngine::Instance();
    return engine->EstimatedCipherLen(plainTextLen);
}

uint32_t EstimatedPlainLen(uint32_t cipherTextLen)
{
    CryptoEngine *engine = CryptoEngine::Instance();
    return engine->EstimatedPlainLen(cipherTextLen);
}
} // namespace cdf
