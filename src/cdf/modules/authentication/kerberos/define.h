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

#include <string>
#include <utility>

#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/define.h"

namespace cdf {

constexpr int MAX_FILE_SIZE = 1024000000;
constexpr int MIN_VALID_KEY = 0x20161111;
constexpr int MAX_VALID_KEY = 0x20169999;
constexpr int MAX_KEYPASS_LEN = 1048576;
constexpr int MAX_ALLOWED_NAME_LENGTH = 1048576;

constexpr CryptoSymAlg KRB_DEFAULT_CRYPTO_SYMALG = CryptoSymAlg::AES256_GCM;
constexpr uint32_t KRB_DEFAULT_DOMAIN_ID = 0;
constexpr KeyManagerTy DEFAULT_KRB_KEY_MANAGER_TY = KeyManagerTy::OPENBAO;

enum class KrbRc : int {
    CDF_OK = 0,            // Success
    CDF_ERROR = 1,         // Error
    CDF_INVALID_PARAM = 2, // Invalid Param
    CDF_KEY_EXPIRED = 3,   // Key Expired
    CDF_UNINITED = 4,      // UnInited
};

struct KrbResult {
    uint32_t mResult = 0;
    std::string mMessage;

    KrbResult() = default;
    KrbResult(uint32_t result, std::string message) : mResult(result), mMessage(std::move(message))
    {}

    KrbResult(KrbRc result, std::string message) : mResult(static_cast<uint32_t>(result)), mMessage(std::move(message))
    {}

    ~KrbResult() = default;

    KrbRc GetKrbRc() const
    {
        return static_cast<KrbRc>(mResult);
    }

    bool OK() const
    {
        return mResult == 0;
    }
};

} // namespace cdf
