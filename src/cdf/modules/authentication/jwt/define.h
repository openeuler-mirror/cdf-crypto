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

#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>

#include "cdf/base/common_define.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/define.h"

namespace cdf {

constexpr CryptoHmacAlg JWT_DEFAULT_HMAC_ALG = CryptoHmacAlg::HMAC_SHA256;

enum class JwtAuthMode : int {
    INTERNAL_KEY = 0,
    EXTERNAL_KEY = 1,
    UNKNOWN,
};

enum class JwtAuthRC : int {
    OK = 0,                      /* success */
    ERROR = 200,                 /* error */
    NEW_OBJ_FAIL = 201,          /* new object fail */
    NOT_SUPPORTED = 202,         /* not supported type */
    PARAM_INVALID = 203,         /* param wrong */
    BASE64_ENCODE_FAIL = 204,    /* base64 encode fail */
    BASE64_DECODE_FAIL = 205,    /* base64 decode fail */
    HMAC_ENCODE_FAIL = 206,      /* hmac encode fail */
    OPENSSL_INIT_FAIL = 207,     /* openssl init fail */
    TOKEN_EXPIRED = 208,         /* token expired */
    CREATE_TOKEN_FAIL = 209,     /* create token fail */
    TOKEN_VALIDATE_FAIL = 210,   /* validate token fail */
    KEY_PASS_INVALID = 211,      /* key pass invalid */
    KEY_MANAGER_INIT_FAIL = 212, /* key manager init fail */
    ENCRYPT_FAIL = 213,          /* encrypt fail */
    DECRYPT_FAIL = 214,          /* decrypt fail */
    ERASE_KEY_FAIL = 215,        /* erase key fail */
    REFRESH_KEY_FAIL = 216,      /* refresh key fail */
    SET_KEY_FAIL = 217,          /* set key fail */
    UNKNOWN,
};

constexpr uint16_t JWT_EXPIRE_TIME_MAX_MINUTE = 32767;
constexpr uint16_t JWT_SECONDS_PER_MINUTE = 60;
constexpr uint16_t JWT_MINUTES_PER_HOUR = 60;
constexpr uint32_t JWT_INPUT_LENGTH_MAX = 1024 * 1024 * 100;
constexpr uint32_t JWT_KEY_LENGTH_MAX = 1048576; // 与加密接口最大明文长度要求一致
constexpr uint16_t HMAC_SHA256_MIN_LENGTH = 32;
constexpr uint16_t HMAC_SHA384_MIN_LENGTH = 48;
constexpr uint16_t HMAC_SHA512_MIN_LENGTH = 64;
constexpr uint32_t MAX_ALLOWED_LENGTH = 1024 * 1024;
constexpr uint32_t DOMAIN_ID_MAX = 1023;

constexpr auto JWT_DEFAULT_SYM_ENC_ALG = CryptoSymAlg::AES256_GCM;

} // namespace cdf
