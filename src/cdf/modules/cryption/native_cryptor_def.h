// Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#include <vector>

#include "cdf/base/crypt_error.h"

namespace cdf {
enum class CcsecCryptMacAlgId {
    CCSEC_CRYPT_MAC_HMAC_SHA256 = 0,
    CCSEC_CRYPT_MAC_HMAC_SHA384,
    CCSEC_CRYPT_MAC_HMAC_SHA512,
    CCSEC_CRYPT_MAC_HMAC_SM3
};

/**
 * @param   ccsecCryptMacAlgId [IN] HMAC algorithm ID (Only the HMAC algorithm ID is supported, including
 * CCSEC_CRYPT_MAC_HMAC_SHA256, CCSEC_CRYPT_MAC_HMAC_SHA384, CCSEC_CRYPT_MAC_HMAC_SHA512,
 * CCSEC_CRYPT_MAC_HMAC_SM3) 默认CCSEC_CRYPT_MAC_HMAC_SHA256
 * @param   iterationTimes [IN] Iteration times. The value can be a positive integer that is not 0. The value
 * can be 1000 in special performance scenarios. The default value is 100000,
 * 10000000 is recommended in scenarios where performance is insensitive or
 * security requirements are high. The value range is [1000, 20000000]. 默认100000
 * @param   outLen [IN] Length of the derived key. The value range is [32, 128]. 默认64
 * @param   salt [IN] Salt value, input by the user. length [16, 64].
 */
struct Pbkdf2ConfigStruct {
    CcsecCryptMacAlgId ccsecCryptMacAlgId{CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA256};
    uint32_t iterationTimes{100000};
    uint32_t outLen{64};
    std::vector<uint8_t> salt;
};
} // namespace cdf
