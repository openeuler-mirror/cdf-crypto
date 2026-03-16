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

#include <cstddef>
#include <string>
#include <utility>

#include "cdf/modules/cryption/define.h"

namespace cdf {

/**
 * @brief Get the estimated output length for a given hmac algorithm.
 * @param[in] hmacAlg
 * @return the estimated output length in bytes.
 */
size_t GetEstimateHmacOutLen(CryptoHmacAlg hmacAlg);

/**
 * @brief Calculate the Hmac.
 * @param[in] hmacAgl
 * @param[in] key
 * @param[in] input
 * @param[in] outData
 * @param[in] outLen
 * @return CryptionRC::OK on success, other error code on failure.
 */
CryptionRC NativeHmac(CryptoHmacAlg hmacAlg, std::string_view key, std::string_view input, unsigned char *outData,
                      uint32_t *outLen);

} // namespace cdf
