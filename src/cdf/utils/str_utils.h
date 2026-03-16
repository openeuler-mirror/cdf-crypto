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
#include <limits>
#include <string>
#include <vector>

namespace cdf {

class StrUtils {
public:
    static bool StrToLong(std::string_view src, long &value) noexcept
    {
        try {
            value = std::stol(src.data());
        } catch (std::exception &e) {
            return false;
        }
        return true;
    }

    static bool StrToInt(std::string_view src, int &value) noexcept
    {
        try {
            value = std::stoi(src.data());
        } catch (std::exception &e) {
            return false;
        }
        return true;
    }

    static bool StrToInt64(std::string_view src, int64_t &value) noexcept
    {
        try {
            auto tmp = std::stoll(src.data()); // long long (at least 64 bit) to int64_t
            if (tmp < static_cast<long long>(std::numeric_limits<int64_t>::min()) ||
                tmp > static_cast<long long>(std::numeric_limits<int64_t>::max())) {
                value = 0; // reset output value
                return false;
            }
            value = static_cast<int64_t>(tmp); // long long -> int64_t
        } catch (std::exception &e) {
            return false;
        }
        return true;
    }

    static bool StrToU32(const std::string &src, uint32_t &value) noexcept
    {
        try {
            auto tmp = std::stoll(src);
            if (tmp < static_cast<long long>(std::numeric_limits<uint32_t>::min()) ||
                tmp > static_cast<long long>(std::numeric_limits<uint32_t>::max())) {
                value = 0; // reset output value
                return false;
            }
            value = static_cast<uint32_t>(tmp); // int -> uint32_t
        } catch (std::exception &e) {
            return false;
        }
        return true;
    }

    static void Split(std::string_view src, std::string_view sep, std::vector<std::string> &out)
    {
        if (sep.empty()) {
            return;
        }
        std::string::size_type pos1 = 0;
        std::string::size_type pos2 = src.find(sep);

        std::string tmpStr;
        while (std::string::npos != pos2) {
            tmpStr = src.substr(pos1, pos2 - pos1);
            out.emplace_back(tmpStr);
            pos1 = pos2 + sep.size();
            pos2 = src.find(sep, pos1);
        }

        if (pos1 != src.size()) {
            tmpStr = src.substr(pos1);
            out.emplace_back(tmpStr);
        }
    }

    static std::vector<std::string> Split(std::string_view src, std::string_view sep)
    {
        std::vector<std::string> out;
        Split(src, sep, out);
        return out;
    }
};

} // namespace cdf
