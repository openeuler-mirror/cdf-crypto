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

#include "cdf/modules/cryption/hmac.h"

#include <string>
#include <utility>

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/custom_logger.h"
#include "cdf/modules/cryption/define.h"

#include "openssl/hmac.h"

namespace cdf {

namespace {
constexpr uint16_t HMAC_SHA256_LENGTH = 32;
constexpr uint16_t HMAC_SHA384_LENGTH = 48;
constexpr uint16_t HMAC_SHA512_LENGTH = 64;

CryptionRC CheckKeyLen(CryptoHmacAlg hmacAlg, const uint32_t keyLen)
{
    CryptionRC ret = CryptionRC::OK;
    if (hmacAlg == CryptoHmacAlg::HMAC_SHA256) {
        if (keyLen < HMAC_SHA256_LENGTH) {
            ret = CryptionRC::INVALID_PARAM;
        }
    } else if (hmacAlg == CryptoHmacAlg::HMAC_SHA384) {
        if (keyLen < HMAC_SHA384_LENGTH) {
            ret = CryptionRC::INVALID_PARAM;
        }
    } else if (hmacAlg == CryptoHmacAlg::HMAC_SHA512) {
        if (keyLen < HMAC_SHA512_LENGTH) {
            ret = CryptionRC::INVALID_PARAM;
        }
    } else {
        ret = CryptionRC::INVALID_PARAM;
    }
    return ret;
}

inline uint16_t GetKeyLenMin(CryptoHmacAlg hmacAlg)
{
    switch (hmacAlg) {
        case CryptoHmacAlg::HMAC_SHA256:
            return HMAC_SHA256_LENGTH;
        case CryptoHmacAlg::HMAC_SHA384:
            return HMAC_SHA384_LENGTH;
        case CryptoHmacAlg::HMAC_SHA512:
            return HMAC_SHA512_LENGTH;
        default:
            CCSEC_LOG_ERROR("|GetKeyLenMin|returnF|Failed to get hmac key min length as algorithm "
                            << static_cast<int>(hmacAlg) << " is not supported by this program.");
            return 0;
    }
}
} // namespace

size_t GetEstimateHmacOutLen(CryptoHmacAlg hmacAlg)
{
    switch (hmacAlg) {
        case CryptoHmacAlg::HMAC_SHA256:
            return HMAC_SHA256_LENGTH;
        case CryptoHmacAlg::HMAC_SHA384:
            return HMAC_SHA384_LENGTH;
        case CryptoHmacAlg::HMAC_SHA512:
            return HMAC_SHA512_LENGTH;
        default:
            CCSEC_LOG_ERROR("|GetEstimateHmacOutLen|returnF|Failed to "
                            "calculate hmac encode length as algorithm "
                            "" << static_cast<int>(hmacAlg) << " is not supported by this program.");
            return 0;
    }
}

CryptionRC NativeHmac(CryptoHmacAlg hmacAlg, std::string_view key, std::string_view input, unsigned char *outData,
                      uint32_t *outLen)
{
    if (CCSEC_UNLIKELY(key.empty()) || CCSEC_UNLIKELY(input.empty())) {
        CCSEC_LOG_ERROR("|NativeHmac|returnF|Invalid arguments, key or input is empty.");
        return CryptionRC::INVALID_PARAM;
    }

    if (CheckKeyLen(hmacAlg, key.size()) != CryptionRC::OK) {
        CCSEC_LOG_ERROR("|NativeHmac|returnF|Invalid arguments, key length: "
                        << key.size() << " is too short, expect at least " << GetKeyLenMin(hmacAlg));
        return CryptionRC::INVALID_PARAM;
    }

    const EVP_MD *evpMd = nullptr;
    if (hmacAlg == CryptoHmacAlg::HMAC_SHA256) {
        evpMd = EVP_sha256();
    } else if (hmacAlg == CryptoHmacAlg::HMAC_SHA384) {
        evpMd = EVP_sha384();
    } else if (hmacAlg == CryptoHmacAlg::HMAC_SHA512) {
        evpMd = EVP_sha512();
    } else {
        CCSEC_LOG_ERROR("|NativeHmac|returnF|Failed to encode with hmac "
                        "algorithm: " << static_cast<int>(hmacAlg) << "  is not supported by this program.");
        return CryptionRC::INVALID_PARAM;
    }

    if (CCSEC_UNLIKELY(evpMd == nullptr)) {
        CCSEC_LOG_ERROR("|NativeHmac|returnF|Failed to init OpenSSL connector.");
        return CryptionRC::ERROR;
    }

    auto ctx = HMAC(evpMd,                                                 // has algorithm
                    key.data(),                                            // key
                    key.size(),                                            //
                    reinterpret_cast<const unsigned char *>(input.data()), // input
                    input.size(),                                          //
                    outData,                                               // output
                    outLen);
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|NativeHmac|returnF|Failed to HMAC");
        return CryptionRC::ERROR;
    }
    if (CCSEC_UNLIKELY(outData == nullptr)) {
        CCSEC_LOG_ERROR("|NativeHmac|returnF|Failed in OpenSSL HMAC function call");
        return CryptionRC::ERROR;
    } else {
        // NOTE if outLen is nullptr, it means user does not want a returned
        // outLen, so we simply returns success;
        return CryptionRC::OK;
    }
}

} // namespace cdf
