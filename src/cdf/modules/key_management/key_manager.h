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

#include <cstdint>
#include <string>
#include <utility>

#include "cdf/base/custom_logger.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/define.h"

namespace cdf {

class KeyManager {
public:
    virtual ~KeyManager() = default;

    /**
     * @brief Initialize the key manager with given arguments.
     * @param[in] accessToken The temporily access token.
     * @param[in] domainCount
     * @return KeyManagerRC::OK on success, other error code on failure.
     * @remark
     * - Repeated call of legit Init() will always return success, but will
     * print warning, such as "Key manager has already been inited."
     * - Support KeyMangerTy::OPENBAO and KeyMangerTy::VAULT only.
     */
    virtual KeyManagerRC Init(std::string_view exePath, std::string_view accessToken, uint32_t domainCount) = 0;

    /**
     * @brief Get key manager type.
     * @return KeyManagerTy.
     */
    virtual KeyManagerTy Type() const = 0;

    /**
     * @brief Get the domain number.
     * @return uint32_t.
     */
    virtual uint32_t DomainCount() const = 0;

    /**
     * @brief Check if key manager is inited.
     * @return true if inited, false otherwise.
     * @remark
     * - For Openbal/Valut: Check if the given accessToken is still valid.
     */
    virtual bool CheckInited() const = 0;

    /**
     * @brief Uninit key manager.
     * @return KeyManagerRC::OK on success, other error code on failure.
     * @remark
     * - For Openbal/Valut: Remove all the keys that is created by us.
     */
    virtual KeyManagerRC UnInit() = 0;

    // -----------------------
    // Common Key Manipulation
    // -----------------------

    /**
     * @brief Create key for the given domain id.
     * @param[in] domainId
     * @return std::pair<KeyManagerRC, uint32_t> {KeyManagerRC::OK, keyId} on
     * success, {KeyManagerRC::[OTHER_ERROR_CODE], 0} on failure.
     */
    virtual std::pair<KeyManagerRC, uint32_t> CreateKey(uint32_t domainId) = 0;

    /**
     * @brief Remove the specified key from given domain id.
     * @param[in] domainId
     * @param[in] keyId
     * @return KeyManagerRC::OK on success, other error code on failure.
     */
    virtual KeyManagerRC RemoveKey(uint32_t domainId, uint32_t keyId) = 0;

    /**
     * @brief Display all keys.
     * @return KeyManagerRC::OK on success, other error code on failure.
     */
    virtual KeyManagerRC DisplayAllKey() const = 0;

    /**
     * @brief Disaply the keys in the given domain
     * @param[in] domainId
     * @return KeyManagerRC::OK on success, other error code on failure.
     */
    virtual KeyManagerRC DisplayKey(uint32_t domainId) const = 0;

    /**
     * @brief Check whether any domain keys will expire after certain days.
     * @param[in] domainId
     * @param[in] lead The leading days (e.g. lead = 1 means check if master key
     * will expire after 1 day).
     * @return KeyManagerRC::OK on "master key will not expire",
     * KeyManagerRC::KEY_EXPIRED on "master key will expire", other error code
     * on failure.
     */
    virtual KeyManagerRC CheckDomainKeysExpired(uint32_t domainId, uint32_t lead) = 0;

    /**
     * @brief Check whether any domain keys will expire after certain days, if
     * expired, automatically updates the master key.
     * @param[in] domainId
     * @param[in] lead The leading days (e.g. lead = 1 means check if root key
     * will expired after 1 day).
     * @return KeyManagerRC::OK on success, other error code on failure.
     */
    virtual KeyManagerRC CheckDomainKeysExpiredAndAutoUpdate(uint32_t domainId, uint32_t lead) = 0;
};

} // namespace cdf
