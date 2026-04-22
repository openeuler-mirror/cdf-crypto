// Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "securec.h"

#include "cdf/modules/cryption/native_cryptor.h"

namespace cdf {

constexpr uint32_t IV_OFFSET_DEFAULT = 0;
constexpr uint32_t IV_LEN_DEFAULT = 12;  // 默认IV长度
constexpr uint32_t IV_LEN_SM4 = 16;      // 默认IV长度
constexpr uint32_t AAD_LEN_DEFAULT = 16; // ADD长度 常用16 这里默认16
constexpr uint32_t TAG_LEN_DEFAULT = 16; // 默认TAG长度
constexpr uint32_t PBKDF2_ITERATION_TIMES_DEFAULT = 100000;
constexpr uint32_t PBKDF2_ITERATION_TIMES_MIN = 1000;
constexpr uint32_t PBKDF2_ITERATION_TIMES_MAX = 20000000;
constexpr CcsecCryptMacAlgId PBKDF2_ALGID_DEFAULT = CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA256;
constexpr uint32_t PBKDF2_OUT_LEN_DEFAULT = 64; // 最少256比特 这里取512比特 长度为512/8
constexpr uint32_t PBKDF2_OUT_LEN_MIN = 32;
constexpr uint32_t PBKDF2_OUT_LEN_MAX = 128;
constexpr uint32_t PBKDF2_SALT_LEN_MIN = 16;
constexpr uint32_t PBKDF2_SALT_LEN_MAX = 64;
constexpr uint32_t PBKDF2_OUT_OFFSET = 7;

class CryptoConfig {
public:
    /*
     * cipherText data format :|IV||AAD (opt)|TAG(opt)|CIPHER DATA|
     * ------------------- Bytes :|12 | 16           | 16         |      ?             |
     * --------------------------- |-> mIVOffset                |-> mCipherOffset
     * --------------------------------|-> mAADOffset
     * ---------------------------------------------|-> mTagOffset
     */
    // 构造函数，初始化配置
    explicit CryptoConfig(CcsecCipherSuite cipherSuite = CcsecCipherSuite::CCSEC_UNSPECIFIED)
        : mCipherSuite(cipherSuite),
          /* IV use 12Bytes(96bits) */
          mIVLen(IV_LEN_DEFAULT),
          /* AAD use 16Bytes(128bits) */
          mAADLen(AAD_LEN_DEFAULT),
          /* Tag use 16Bytes(128bits) */
          mTagLen(TAG_LEN_DEFAULT),
          mIVOffset(IV_OFFSET_DEFAULT),
          mAADOffset(mIVOffset + mIVLen),
          mTagOffset(mAADOffset + mAADLen),
          mCipherOffset(mTagOffset + mTagLen)
    {}

    CcsecCipherSuite GetCipherSuite() const
    {
        return mCipherSuite;
    }

    uint32_t GetIVLength() const
    {
        if (mCipherSuite == CcsecCipherSuite::CCSEC_SM4_CTR) {
            return IV_LEN_SM4;
        }
        return mIVLen;
    }

    uint32_t GetAADLength() const
    {
        if (mCipherSuite == CcsecCipherSuite::CCSEC_SM4_CTR) {
            return IV_LEN_SM4;
        }
        return mAADLen;
    }

    uint32_t GetTagLength() const
    {
        return mTagLen;
    }

    off_t GetIVOffset() const
    {
        return mIVOffset;
    }

    off_t GetAADOffset() const
    {
        return mAADOffset;
    }

    off_t GetTagOffset() const
    {
        return mTagOffset;
    }

    off_t GetCipherOffset() const
    {
        return mCipherOffset;
    }

    void SetMCipherSuite(CcsecCipherSuite cipherSuite)
    {
        CryptoConfig::mCipherSuite = cipherSuite;
    }

private:
    CcsecCipherSuite mCipherSuite;
    const uint32_t mIVLen;
    const uint32_t mAADLen;
    const uint32_t mTagLen;
    off_t mIVOffset;
    off_t mAADOffset;
    off_t mTagOffset;
    off_t mCipherOffset;
};

class CryptoEngine {
public:
    CryptoEngine() : cryptoConfig(CcsecCipherSuite::CCSEC_UNSPECIFIED){};
    ~CryptoEngine() = default;

public:
    static CryptoEngine *Instance()
    {
        static CryptoEngine instance;
        return &instance;
    }

    int32_t InitCrypto(CcsecCipherSuite suite);

    int32_t Encrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *plainText,
                    const uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen);

    int32_t Decrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *cipherText,
                    const uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen);

    uint32_t EstimatedCipherLen(uint32_t plainTextLen) const;

    uint32_t EstimatedPlainLen(uint32_t cipherTextLen) const;

    CryptoConfig &GetCryptoConfig()
    {
        return cryptoConfig;
    }

    int32_t Pbkdf2Hmac(const std::vector<uint8_t> &key, const Pbkdf2ConfigStruct &pbkdf2ConfigStruct,
                       std::vector<uint8_t> &outBase64);

    int32_t GetPbkdf2Config(const std::vector<uint8_t> &base64Code, Pbkdf2ConfigStruct &pbkdf2ConfigStruct);

private:
    static std::unique_ptr<CryptoEngine> CryptoEngineInstance;
    CryptoConfig cryptoConfig;

    static std::mutex cryptoEngineMutex;

    int32_t OpensslEncrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                           const uint8_t *plainText, const uint32_t plainTextLen, uint8_t *cipherText,
                           uint32_t *cipherTextLen);

    int32_t OpensslDecrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                           const uint8_t *cipherText, const uint32_t cipherTextLen,
                           uint8_t *plainText, uint32_t *plainTextLen);

    int32_t OpensslCcmDecrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                              const uint8_t *cipherText, const uint32_t cipherTextLen,
                              uint8_t *plainText, uint32_t *plainTextLen);

    int32_t OpensslCcmEncrypt(const uint8_t *cryptoKey, [[maybe_unused]]const uint32_t cryptoKeyLen,
                              const uint8_t *plainText, const uint32_t plainTextLen, uint8_t *cipherText,
                              uint32_t *cipherTextLen);
};

/**
 * @brief 设置加密用的算法套
 * @param cipherSuite 加解密算法套
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
int32_t InitCrypto(CcsecCipherSuite cipherSuite);

/**
 * @brief 通过密钥的方式对文本进行加密
 * @param plainText [IN] 明文
 * @param plainTextLen [IN] 明文长度
 * @param cipherText [OUT] 密文
 * @param cipherTextLen [IN/OUT] 密文长度
 * @param cryptoKey [IN] 密钥
 * @param cryptoKeyLen [IN] 密钥长度
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
int32_t KeyEncrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *plainText,
                   const uint32_t plainTextLen, uint8_t *cipherText, uint32_t *cipherTextLen);

/**
 * @brief 通过密钥的方式对文本进行解密
 * @param cipherText [IN] 密文
 * @param cipherTextLen [IN] 密文长度
 * @param plainText [OUT] 明文
 * @param plainTextLen [OUT] 明文长度
 * @param cryptoKey [IN] 密钥
 * @param cryptoKeyLen [IN] 密钥长度
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
int32_t KeyDecrypt(const uint8_t *cryptoKey, const uint32_t cryptoKeyLen, const uint8_t *cipherText,
                   const uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen);

/**
 * @brief 根据明文预估密文长度 应用于Encrypt接口
 * @param plainTextLen  [IN] 明文长度
 * @return 返回预估的密文长度
 */
uint32_t EstimatedCipherLen(uint32_t plainTextLen);

/**
 * @brief 根据密文预估明文长度 应用于Decrypt接口
 * @param cipherTextLen [IN] 密文长度
 * @return 返回预估的明文长度
 */
uint32_t EstimatedPlainLen(uint32_t cipherTextLen);
} // namespace cdf
