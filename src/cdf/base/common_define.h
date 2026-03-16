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

#include <cstdint>
#include <cstdlib>
#include <string_view>
#include <vector>

namespace cdf {

constexpr int NUM_0 = 0;
constexpr int NUM_1 = 1;
constexpr int NUM_2 = 2;
constexpr int NUM_3 = 3;
constexpr int NUM_4 = 4;
constexpr int NUM_5 = 5;
constexpr int NUM_6 = 6;
constexpr int NUM_7 = 7;
constexpr int NUM_8 = 8;
constexpr int NUM_9 = 9;
constexpr int NUM_10 = 10;
constexpr int NUM_11 = 11;
constexpr int NUM_12 = 12;
constexpr int NUM_14 = 14;
constexpr int NUM_24 = 24;
constexpr int NUM_26 = 26;
constexpr int NUM_28 = 28;
constexpr int NUM_29 = 29;
constexpr int NUM_30 = 30;
constexpr int NUM_31 = 31;
constexpr int NUM_100 = 100;
constexpr int NUM_128 = 128;
constexpr int NUM_256 = 256;
constexpr int NUM_400 = 400;
constexpr int NUM_1024 = 1024;
constexpr int NUM_1900 = 1900;
constexpr int NUM_2048 = 2048;
constexpr int NUM_4096 = 4096;

enum class LogRc {
    SUCCESS = 0,
    INVALID_PARAM,
    INITIALIZED_FAILED,
    INVALID_LEVEL
};

// Define templates for enum range check
// see: https://stackoverflow.com/a/33091821
//
// Example:
// -----------------
// enum class Test {
//   A = 1,
//   B = 2,
//   C = 3
// }
//
// using TestCheck = EnumCheck<Test, Test::A, Test::B, Test::C>;
//
// TestCheck::isValue(...);
// -----------------

template <typename EnumType, EnumType... Values> class EnumCheck;

template <typename EnumType> class EnumCheck<EnumType> {
public:
    template <typename IntType> static bool constexpr IsValue(IntType)
    {
        return false;
    }
};

template <typename EnumType, EnumType V, EnumType... Next>
class EnumCheck<EnumType, V, Next...> : private EnumCheck<EnumType, Next...> {
    using Super = EnumCheck<EnumType, Next...>;

public:
    template <typename IntType> static bool constexpr IsValue(IntType v)
    {
        return v == static_cast<IntType>(V) || Super::IsValue(v);
    }
};

// -----------------
// String View
// -----------------

inline std::string_view MakeStringView(const std::vector<std::byte> &in)
{
    return {reinterpret_cast<const char *>(in.data()), in.size()};
}

inline std::string_view MakeStringView(const std::vector<char> &in)
{
    return {reinterpret_cast<const char *>(in.data()), in.size()};
}

// hint: uint8_t == unsigned char
inline std::string_view MakeStringView(const std::vector<unsigned char> &in)
{
    return {reinterpret_cast<const char *>(in.data()), in.size()};
}

// -----------------
// std::byte helper
// -----------------

inline std::byte ToByte(unsigned char uc)
{
    return static_cast<std::byte>(uc);
}

inline std::byte ToByte(char c)
{
    return ToByte(static_cast<unsigned char>(c));
}

} // namespace cdf
