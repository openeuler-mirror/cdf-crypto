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

#include "cdf/utils/base64.h"

#include <array>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"

namespace cdf {

namespace {
const std::string_view BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789+/";
inline bool IsBase64(unsigned char c)
{
    return ((isalnum(c) != 0) || (c == '+') || (c == '/'));
}
} // namespace

std::vector<std::byte> Base64Encode(const char *buf, unsigned int bufLen)
{
    if (buf == nullptr) {
        CCSEC_LOG_ERROR("Base64Encode Failed, input buffer is nullptr");
        return {};
    }
    std::vector<std::byte> ret;
    uint32_t i = 0;
    uint32_t j = 0;
    std::array<unsigned char, NUM_3> charArray3;
    std::array<unsigned char, NUM_4> charArray4;

    constexpr uint8_t masK1 = 0xfc;
    constexpr uint8_t masK2 = 0x03;
    constexpr uint8_t masK3 = 0xf0;
    constexpr uint8_t masK4 = 0x0f;
    constexpr uint8_t masK5 = 0xc0;
    constexpr uint8_t masK6 = 0x3f;

    while ((bufLen--) != 0U) {
        charArray3[i++] = *(buf++);
        if (i == NUM_3) {
            charArray4[NUM_0] = (charArray3[NUM_0] & masK1) >> NUM_2;
            charArray4[NUM_1] = ((charArray3[NUM_0] & masK2) << NUM_4) + ((charArray3[NUM_1] & masK3) >> NUM_4);
            charArray4[NUM_2] = ((charArray3[NUM_1] & masK4) << NUM_2) + ((charArray3[NUM_2] & masK5) >> NUM_6);
            charArray4[NUM_3] = charArray3[NUM_2] & masK6;

            for (i = 0; i < charArray4.size(); i++) {
                ret.push_back(static_cast<std::byte>(BASE64_CHARS[charArray4[i]]));
            }
            i = 0;
        }
    }

    if (i != 0) {
        for (j = i; j < charArray3.size(); j++) {
            charArray3[j] = '\0';
        }

        charArray4[NUM_0] = (charArray3[NUM_0] & masK1) >> NUM_2;
        charArray4[NUM_1] = ((charArray3[NUM_0] & masK2) << NUM_4) + ((charArray3[NUM_1] & masK3) >> NUM_4);
        charArray4[NUM_2] = ((charArray3[NUM_1] & masK4) << NUM_2) + ((charArray3[NUM_2] & masK5) >> NUM_6);
        charArray4[NUM_3] = charArray3[NUM_2] & masK6;

        for (j = 0; (j < i + 1); j++) {
            ret.push_back(static_cast<std::byte>(BASE64_CHARS[charArray4[j]]));
        }

        while ((i++ < charArray3.size())) {
            ret.push_back(static_cast<std::byte>('='));
        }
    }

    return ret;
}

std::vector<unsigned char> Base64Decode(std::string_view encodedString)
{
    auto inLen = encodedString.size();
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t in = 0;
    std::array<unsigned char, NUM_3> charArray3;
    std::array<unsigned char, NUM_4> charArray4;
    std::vector<unsigned char> ret;

    constexpr uint8_t masK1 = 0x30;
    constexpr uint8_t masK2 = 0xf;
    constexpr uint8_t masK3 = 0x3c;
    constexpr uint8_t masK4 = 0x3;

    while (((inLen--) != 0) && (encodedString[in] != '=') && IsBase64(encodedString[in])) {
        charArray4[i++] = encodedString[in];
        in++;
        if (i == charArray4.size()) {
            for (i = 0; i < charArray4.size(); i++) {
                charArray4[i] = BASE64_CHARS.find(charArray4[i]);
            }

            charArray3[NUM_0] = (charArray4[NUM_0] << NUM_2) + ((charArray4[NUM_1] & masK1) >> NUM_4);
            charArray3[NUM_1] = ((charArray4[NUM_1] & masK2) << NUM_4) + ((charArray4[NUM_2] & masK3) >> NUM_2);
            charArray3[NUM_2] = ((charArray4[NUM_2] & masK4) << NUM_6) + charArray4[NUM_3];

            for (i = 0; i < charArray3.size(); i++) {
                ret.push_back(charArray3[i]);
            }

            i = 0;
        }
    }

    if (i) {
        for (j = i; j < charArray4.size(); j++) {
            charArray4[j] = 0;
        }

        for (j = 0; j < charArray4.size(); j++) {
            charArray4[j] = BASE64_CHARS.find(charArray4[j]);
        }

        charArray3[NUM_0] = (charArray4[NUM_0] << NUM_2) + ((charArray4[NUM_1] & masK1) >> NUM_4);
        charArray3[NUM_1] = ((charArray4[NUM_1] & masK2) << NUM_4) + ((charArray4[NUM_2] & masK3) >> NUM_2);
        charArray3[NUM_2] = ((charArray4[NUM_2] & masK4) << NUM_6) + charArray4[NUM_3];

        for (j = 0; (j < i - 1); j++) {
            ret.push_back(charArray3[j]);
        }
    }
    return ret;
}

} // namespace cdf
