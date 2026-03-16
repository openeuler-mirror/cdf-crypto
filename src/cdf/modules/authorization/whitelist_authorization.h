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
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cdf/modules/authorization/error_code.h"

namespace cdf {

class WhitelistAuthorization {
public:
    WhitelistAuthorization() = default;
    ~WhitelistAuthorization() = default;

    // 认证配置初始化
    // @param conf 认证配置信息，
    // @return AUTH_OK，成功，否则失败
    // non-thread-safe function
    AuthRC Initialize(std::string_view conf);

    // 认证鉴权
    // @param principal 用户名
    // @param resource 需要操作的资源（保留参数，用于未来功能扩展，当前版本未启用）
    // @param operation 对资源的操作（保留参数，用于未来功能扩展，当前版本未启用）
    // @return AUTH_OK，成功，否则失败
    // thread-safe
    AuthRC CheckPermission(std::string_view principal, [[maybe_unused]] std::string_view resource,
                           [[maybe_unused]] std::string_view operation);

    // 获取所有的用户
    // @param principals 传出参数
    // @return AUTH_OK，成功，否则失败
    // thread-safe
    AuthRC GetAllPrincipals(std::vector<std::string> &principals);

    // 清理认证信息
    // @return AUTH_OK，成功，否则失败
    // non-thread-safe
    AuthRC UnInitialize();

private:
    std::map<std::string, bool> whitelist_;
    static constexpr uint32_t MAX_ALLOWED_NAME_LENGTH = 1024 * 1024;
    static constexpr uint32_t MAX_ALLOWED_CONF_LENGTH = 1024 * 1024 * 100;
};

} // namespace cdf
