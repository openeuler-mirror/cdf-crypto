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

#include "cdf/modules/authentication/jwt/jwt_token.h"

#include <string>

#include "securec.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/custom_logger.h"
#include "cdf/modules/authentication/jwt/define.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/cryption/km_cryptor.h"
#include "cdf/modules/key_management/define.h"

namespace cdf {

namespace {
constexpr uint16_t SECONDS_PER_HOUR = 3600;
}

std::string JwtTokenHeader::ToString()
{
    std::ostringstream oss;
    oss << "alg: " << static_cast<int>(mAlg_) << "; expireTime: " << mExpireTimeMinute_
        << "; createTime:" << mCreateTimeSec_ << ";";
    return oss.str();
}

JwtTokenHeader::JwtTokenHeader(CryptoHmacAlg algType, int16_t expireTime)
    : mAlg_(algType), mExpireTimeMinute_(expireTime)
{
    auto now = timespec{0, 0};
    clock_gettime(CLOCK_REALTIME, &now);
    mCreateTimeSec_ = static_cast<uint64_t>(now.tv_sec);
}

JwtKeyPass::~JwtKeyPass()
{
    if (oldKey_ != nullptr) {
        (void)memset_s(oldKey_, oldKeyLen_, 0, oldKeyLen_);
        delete[] oldKey_;
        oldKey_ = nullptr;
    }
    if (key_ != nullptr) {
        (void)memset_s(key_, keyLen_, 0, keyLen_);
        delete[] key_;
        key_ = nullptr;
    }
}

bool JwtKeyPass::IsExpired() const
{
    auto now = timespec{0, 0};
    clock_gettime(CLOCK_REALTIME, &now);

    uint64_t keyExpiredSec = serverKeyExpiredHours_ * SECONDS_PER_HOUR;
    return newKeyCreateTimeSec_ + keyExpiredSec < static_cast<uint64_t>(now.tv_sec);
}

bool JwtKeyPass::IsOldKeyExpired() const
{
    auto now = timespec{0, 0};
    clock_gettime(CLOCK_REALTIME, &now);

    uint64_t oldKeyExpiredSec = serverKeyExpiredHours_ * SECONDS_PER_HOUR;
    return oldKeyCreateTimeSec_ + oldKeyExpiredSec < static_cast<uint64_t>(now.tv_sec);
}

JwtAuthRC JwtKeyPass::RefreshKey(const char *key, uint32_t len, KeyManagerTy type, uint32_t domainId, CryptoSymAlg alg)
{
    if (CCSEC_UNLIKELY(key == nullptr || len == 0)) {
        CCSEC_LOG_ERROR("Failed to refresh encryption key, as input key is null.");
        return JwtAuthRC::PARAM_INVALID;
    }
    if (oldKey_ != nullptr) {
        memset_s(oldKey_, oldKeyLen_, 0, oldKeyLen_);
        delete[] oldKey_;
        oldKey_ = nullptr;
    }

    oldKeyLen_ = keyLen_;
    oldKey_ = new (std::nothrow) char[oldKeyLen_];
    if (CCSEC_UNLIKELY(oldKey_ == nullptr)) {
        CCSEC_LOG_ERROR("Failed to new sign hmac char array, probably out of memory");
        return JwtAuthRC::NEW_OBJ_FAIL;
    }

    if (CCSEC_UNLIKELY(memcpy_s(oldKey_, oldKeyLen_, key_, keyLen_) != EOK)) {
        CCSEC_LOG_ERROR("Failed to erase the key.");
        delete[] oldKey_;
        oldKey_ = nullptr;
        return JwtAuthRC::REFRESH_KEY_FAIL;
    }

    oldKeyCreateTimeSec_ = newKeyCreateTimeSec_;
    if (CCSEC_UNLIKELY(SetKey(key, len, type, domainId, alg) != JwtAuthRC::OK)) {
        CCSEC_LOG_ERROR("Failed to new sign hmac char array, probably out of memory");
        return JwtAuthRC::REFRESH_KEY_FAIL;
    }

    return JwtAuthRC::OK;
}

JwtAuthRC JwtKeyPass::SetKey(const char *key, uint32_t len, KeyManagerTy type, uint32_t domainId, CryptoSymAlg alg)
{
    if (CCSEC_UNLIKELY(key == nullptr || len == 0)) {
        CCSEC_LOG_ERROR("Failed to set key to jwt server as key is null.");
        return JwtAuthRC::PARAM_INVALID;
    }

    timespec now{0, 0};
    clock_gettime(CLOCK_REALTIME, &now);

    auto [rc, cipher] = KmCryptor(type).Encrypt(alg, std::string_view(key, len), domainId);
    if (CCSEC_UNLIKELY(rc != CryptionRC::OK)) {
        CCSEC_LOG_ERROR("|JwtKeyPass::SetKey|returnF|key manager encrypt failed");
        return JwtAuthRC::ENCRYPT_FAIL;
    }

    if (key_ != nullptr) {
        memset_s(key_, keyLen_, 0, keyLen_);
        delete[] key_;
        key_ = nullptr;
    }

    keyLen_ = cipher.size();
    key_ = new (std::nothrow) char[keyLen_];
    if (CCSEC_UNLIKELY(key_ == nullptr)) {
        CCSEC_LOG_ERROR("Failed to new sign hmac char array, probably out of memory");
        return JwtAuthRC::NEW_OBJ_FAIL;
    }

    if (CCSEC_UNLIKELY(memcpy_s(key_, keyLen_, cipher.data(), cipher.size()) != EOK)) {
        CCSEC_LOG_ERROR("Failed to set key.");
        delete[] key_;
        key_ = nullptr;
        return JwtAuthRC::SET_KEY_FAIL;
    }

    newKeyCreateTimeSec_ = static_cast<uint64_t>(now.tv_sec);
    return JwtAuthRC::OK;
}

} // namespace cdf
