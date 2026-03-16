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

#include <set>
#include "string"
#include "cdf/base/common_define.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/define.h"

namespace cdf {

enum class PskManagerRC : int {
    OK,
    ERROR,
    INVALID_PARAM,
    UNINITED,
    INIT_FAILED,
    PSK_NOT_EXIST,
    UNSUPPORTED,
    PSK_HAS_EXPIRED,
    ENCRYPTO_FAIL,
    DECRYPTO_FAIL,
    CALL_BACK_UNREGISTED,
    CALL_BACK_EXECUTE_FAILED,
    CALL_BACK_REGISTER_FAILED,
    CALL_BACK_TYPE_MISMATCH,
    CALL_BACK_STANDARD_LIBRARY_EXCEPTION,
    CALL_BACK_UN_KNOWN,
};

struct PskParam {
    std::string issuer;
    std::string subject;
    uint32_t pskLength;
    time_t beginTime;
    uint32_t validDays;
};

struct PskMetaData {
    uint32_t pskId;
    std::string issuer;
    std::string subject;
    uint32_t pskLength;
    uint32_t validDays;
    time_t beginTime;
    time_t endTime;
};

struct PsKManagerInitOptions {
    /* algorithm for secure , enum in see CryptoSymAlg */
    CryptoSymAlg algType = CryptoSymAlg::AES256_GCM;
    /* km option, default openbao */
    KeyManagerTy keyManagerType = KeyManagerTy::OPENBAO;
    /* openbao or vault exePath */
    std::string_view exePath;
    /* openbao or vault accessToken */
    std::string_view accessToken;
    /* domain count */
    uint32_t domainCount = 2;
    /* domain id */
    uint32_t domainId = 0;
    /* PSK max count */
    uint32_t pskMaxCount = 100000;
};

constexpr int PSK_CONTENT_MAX_LENGTH = 512;
// 满足要求的psk安全随机字符串长度
constexpr uint32_t MAX_ALLOWED_LENGTH = 1024 * 1024;
constexpr uint32_t PSK_MAX_COUNT_LIMIT_MIN = 1;
constexpr uint32_t PSK_MAX_COUNT_LIMIT_MAX = 4294967295;
constexpr uint32_t PSK_ISSUER_LENGTH_MIN = 1;
constexpr uint32_t PSK_ISSUER_LENGTH_MAX = 64;
constexpr uint32_t PSK_SUBJECT_LENGTH_MIN = 1;
constexpr uint32_t PSK_SUBJECT_LENGTH_MAX = 64;
constexpr uint32_t PSK_LENGTH_256 = 256;
constexpr uint32_t PSK_LENGTH_384 = 384;
constexpr uint32_t PSK_LENGTH_512 = 512;
constexpr uint32_t PSK_VALID_DAYS_MIN = 1;
constexpr uint32_t PSK_VALID_DAYS_MAX = 365;
constexpr uint32_t DAY_TO_SECOND_TIME = 24 * 60 * 60;

} // namespace cdf