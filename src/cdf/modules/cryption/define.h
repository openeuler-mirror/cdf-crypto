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

#include "cdf/base/common_define.h"

namespace cdf {

enum class CryptionRC : int {
    OK = 0,               // Success
    ERROR = 1,            // Failed
    INVALID_PARAM = 2,    // Failed
    KEY_EXPIRED = 3,      // Failed
    UNINITED = 4,         // Failed
    INIT_FAILED = 5,      // Failed
    DOMAIN_COUNT_INVALID, // failed
    KEY_ACTIVE_FAILED,
};

// -------------------------------
// Symmetric Encryption Algorithms
// -------------------------------

enum class CryptoSymAlg : int {
    AES128_GCM = 0,
    AES256_GCM = 1,
    SM4_CTR = 2,
    AES128_CCM = 3,
    CHACHA20_POLY1305 = 4,
    UNKNOWN
};

// ---------------------------------------------------------
// HMAC (Hash-based Message Authenticationn Code) Algorithms
// ---------------------------------------------------------

// Enum class of hmac algorithms
enum class CryptoHmacAlg : int {
    HMAC_SHA256 = 0,
    HMAC_SHA384 = 1,
    HMAC_SHA512 = 2,
    UNKNOWN
};

enum OpenSSLRC : int {
    ERROR = 0,            // Failed
    OK = 1,               // Success
};

using CryptoHmacAlgCheck =
    EnumCheck<CryptoHmacAlg, CryptoHmacAlg::HMAC_SHA256, CryptoHmacAlg::HMAC_SHA384, CryptoHmacAlg::HMAC_SHA512>;
} // namespace cdf
