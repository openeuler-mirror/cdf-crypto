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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cdf/modules/authentication/jwt/define.h"
#include "cdf/modules/authentication/jwt/option.h"

namespace cdf {

/**
 * @class Jwt Server
 */
class JwtAuthServer {
public:
    JwtAuthServer();
    ~JwtAuthServer();

    /**
     * @brief Start JWT authentication server
     * @return JwtAuthRC::OK on success, other error code on failure.
     * @remark: if jwt server is set to JwtAuthMode::INTERNAL_KEY mode, by default the server would use
     * JWT_DEFAULT_KEY_MANAGER_TY to borrow or init a new key manager.
     */
    JwtAuthRC Start(const CDFDistAuthServerOptions &opt);

    /**
     * @brief Stop JWT authentication server
     * @return JwtAuthRC::OK on success, other error code on failure.
     */
    JwtAuthRC Stop();

    /**
     * @brief Refresh encryption
     * @return JwtAuthRC::OK on success, other error code on failure.
     */
    JwtAuthRC RefreshEncryptionKey(std::string_view newKey);

    /**
     * @brief Stop JWT authentication server
     * @return JwtAuthRC::OK on success, other error code on failure.
     */
    JwtAuthRC SetEncryptionKey(std::string_view newKey);

    /**
     * @brief Get estimated token length (in bytes)
     * @return JwtAuthRC::OK on success, other error code on failure.
     */
    std::pair<JwtAuthRC, uint32_t> EstimateTokenLength(uint32_t inputLen);

    /**
     * @brief Create token with given options.
     * @return JwtAuthRC::OK on success, other error code on failure.
     */
    JwtAuthRC CreateToken(CDFDistAuthCreateTokenOptions &options);

    /**
     * @brief Chekc if the token should be accepted.
     * @return JwtAuthRC::OK on success, other error code on failure.
     */
    JwtAuthRC ValidateToken(const CDFDistAuthValidateTokenOptions &options);

private:
    // pimpl design pattern
    class Impl; // forward declaration
    std::unique_ptr<Impl> impl_;
};

} // namespace cdf
