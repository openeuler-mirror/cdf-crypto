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
#include <istream>
#include <string>
#include <utility>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <memory>
#include "cdf/modules/cryption/define.h"

namespace cdf {
enum class HashAlgorithm : uint32_t {
    UNKNOWN,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    BLAKE2,
    BLAKE2B_512 = BLAKE2,
    BLAKE2S_256,
    BLAKE3,
    SM3,
};

// Hash Implementation Class
class Hash {
public:
    // 构造函数
    explicit Hash(HashAlgorithm algorithm);

    // 析构函数
    ~Hash();

    // 获取摘要长度
    uint32_t DigestSize();

    // 重置哈希上下文
    bool Reset();

    // 更新哈希上下文
    bool Update(std::string_view input);

    // 获取哈希摘要
    bool Finalize(std::vector<char> &output); // return ok/not-ok

private:
    class Impl; // 前置声明Impl类
    std::unique_ptr<Impl> impl_; // 使用unique_ptr管理Impl对象的生命周期
};

/// Function alias

bool HashStream(std::istream &input, HashAlgorithm algorithm, std::vector<char> &output);
bool Sha256Stream(std::istream &input, std::vector<char> &output);
bool Sha256(std::string_view input, std::vector<char> &output);
} // namespace cdf
