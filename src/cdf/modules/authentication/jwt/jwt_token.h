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

#pragma once

#include <cstdint>
#include <limits>
#include <sstream>
#include <string>

#include "cdf/base/ccsec_logger.h"
#include "cdf/modules/authentication/jwt/define.h"
#include "cdf/modules/authentication/jwt/option.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/km_cryptor.h"
#include "cdf/modules/key_management/define.h"

namespace cdf {

class JwtTokenHeader {
public:
    JwtTokenHeader() = default;
    ~JwtTokenHeader() = default;

    explicit JwtTokenHeader(CryptoHmacAlg algType, int16_t expireTime);

    std::string ToString();

    CryptoHmacAlg GetAlgTy()
    {
        return mAlg_;
    }

private:
    CryptoHmacAlg mAlg_ = CryptoHmacAlg::HMAC_SHA256;

    int16_t mExpireTimeMinute_ = 0;
    uint64_t mCreateTimeSec_ = 0;
};

class JwtKeyPass {
public:
    JwtKeyPass() = default;
    ~JwtKeyPass();

    explicit JwtKeyPass(uint64_t expireHours)
    {
        if (expireHours > MAX_ALLOWED_EXPIRE_HOURS) {
            CCSEC_LOG_ERROR("Invalid expire hours: " << expireHours << ", max is: " << MAX_ALLOWED_EXPIRE_HOURS
                            << ", set expire hours to default: " << DEFAULT_SERVER_EXPIRE_HOURS << " and continue");
            serverKeyExpiredHours_ = DEFAULT_SERVER_EXPIRE_HOURS;
        } else {
            serverKeyExpiredHours_ = expireHours;
        }
    }

    // Check if the present key is expired
    bool IsExpired() const;

    // Check if the old key is expired
    bool IsOldKeyExpired() const;

    // Push a new key to key store. The new key will become the present key.
    // Previous present key will be set to the old key. Previous old key will be
    // dropped.
    // - NOTE The input key data is in the raw key format (unencrypted), the key
    // gets encrypted by the given key manager type with the given domain id.
    // - NOTE RefreshKey will return JwtAuthRC::REFRESH_KEY_FAIL if there's no
    // present key.
    JwtAuthRC RefreshKey(const char *key, uint32_t len, KeyManagerTy type, uint32_t domainId, CryptoSymAlg alg);

    // Set the present key. Old key stay unchanged.
    // - NOTE The input key data is in the raw key format (unencrypted), the key gets encrypted by the given key
    // manager type with the given domain id.
    JwtAuthRC SetKey(const char *key, uint32_t len, KeyManagerTy type, uint32_t domainId, CryptoSymAlg alg);

    std::string GetKey()
    {
        return {key_, keyLen_};
    }

    std::string GetOldKey()
    {
        return {oldKey_, oldKeyLen_};
    }

private:
    static constexpr uint64_t DEFAULT_SERVER_EXPIRE_HOURS = 24;
    static constexpr uint64_t MAX_ALLOWED_EXPIRE_HOURS = std::numeric_limits<uint16_t>::max(); // prevent overflow

    // present key (encrypted by Openbao)
    char *key_ = nullptr;
    uint32_t keyLen_ = 0;

    // old key (encrypted by Openbao)
    char *oldKey_ = nullptr;
    uint32_t oldKeyLen_ = 0;
    uint64_t serverKeyExpiredHours_ = DEFAULT_SERVER_EXPIRE_HOURS;
    uint64_t newKeyCreateTimeSec_ = 0;
    uint64_t oldKeyCreateTimeSec_ = 0;
};

} // namespace cdf
