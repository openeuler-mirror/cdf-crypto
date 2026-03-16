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

#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "cdf/base/common_define.h"

namespace cdf {

// Calculate the base64 encoeded length in bytes, given the date length in bytes
inline uint32_t Base64EncodeLen(uint32_t dataLen)
{
    return ((dataLen + 2L) / 3L) * 4L + 1; // add 1 for terminal \0
}

// Base64 Encode
// NOTE the input buf is raw data format, please make sure you have input correct buf and bufLen since there will be no
// check in side this function
std::vector<std::byte> Base64Encode(const char *buf, unsigned int bufLen);

// Base64 Decode
std::vector<unsigned char> Base64Decode(std::string_view encodedString);

} // namespace cdf
