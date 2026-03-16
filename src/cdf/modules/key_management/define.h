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

#include "string"
#include "cdf/base/common_define.h"

namespace cdf {

enum class KeyManagerRC : int {
    OK = 0,               // Success
    ERROR = 1,            // Failed
    INVALID_PARAM = 2,    // Failed
    KEY_EXPIRED = 3,      // Failed
    UNINITED = 4,         // Failed
    INIT_FAILED = 5,      // Failed
    DOMAIN_COUNT_INVALID, // failed
    KEY_ACTIVE_FAILED,
    UNSUPPORTED,
};

enum class KeyManagerTy : int {
    OPENBAO = 0,
    VAULT = 1,
    UNKNOWN = 2,
};

struct KeyInfo {
    uint32_t domainId;
    uint32_t keyId;
    std::string status;      // 密钥状态
    std::string createTime;  // 创建时间
    std::string expiredTime; // 过期时间
};

using KeyManagerTyCheck = EnumCheck<KeyManagerTy, KeyManagerTy::OPENBAO, KeyManagerTy::VAULT>;

} // namespace cdf
