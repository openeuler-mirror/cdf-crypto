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

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iomanip> // 用于 std::setw 和 std::setfill
#include <iostream>
#include <iterator> // 用于 std::begin 和 std::end

#include "cdf/base/ccsec_logger.h"
#include "hash.h"

#include "ossl_wrappers.h"

#ifdef CDF_ENABLE_BLAKE3
#include "blake3.h"
#endif

namespace cdf {
namespace {
constexpr size_t HASH_STREAM_BUFFER_SIZE = 64 * 1024;

const char *GetEvpDigestName(HashAlgorithm algorithm)
{
    switch (algorithm) {
        case HashAlgorithm::SHA1:
            return "SHA1";
        case HashAlgorithm::SHA256:
            return "SHA2-256";
        case HashAlgorithm::SHA384:
            return "SHA2-384";
        case HashAlgorithm::SHA512:
            return "SHA2-512";
        case HashAlgorithm::BLAKE2:
            return "BLAKE2B-512";
        case HashAlgorithm::BLAKE2S_256:
            return "BLAKE2S-256";
        case HashAlgorithm::BLAKE3:
            return "BLAKE3";
        case HashAlgorithm::SM3:
            return "SM3";
        case HashAlgorithm::UNKNOWN:
        default:
            return nullptr;
    }
}
}

class Hash::Impl {
public:
    explicit Impl(HashAlgorithm algorithm)
    {
        const char *digestName = GetEvpDigestName(algorithm);
        if (digestName == nullptr) {
            CCSEC_LOG_ERROR("Hash|END|returnF|Invalid hash algorithm");
            return;
        }

        md_ = ossl::FetchEvpMd(digestName);
        if (md_ == nullptr) {
#ifdef CDF_ENABLE_BLAKE3
            if (algorithm == HashAlgorithm::BLAKE3) {
                blake3Hasher_ = std::make_unique<blake3_hasher>();
                digestSize_ = BLAKE3_OUT_LEN;
                inited_ = true;
                blake3_hasher_init(blake3Hasher_.get());
                return;
            }
#endif
            CCSEC_LOG_ERROR("Hash|END|returnF|unsupported hash algorithm");
            return;
        }
        // 创建hash上下文
        context_ = ossl::UniqueMdCtx(EVP_MD_CTX_new());
        if (context_ == nullptr) {
            CCSEC_LOG_ERROR("Hash|END|returnF|Failed to EVP_MD_CTX_new");
            return;
        }
        digestSize_ = EVP_MD_size(md_.get());
        inited_ = true;
        auto ret = Reset();
        if (!ret) {
            CCSEC_LOG_ERROR("Hash|END|returnF|Reset false");
        }
    }

    ~Impl()
    {
        digestSize_ = 0;
    }

    uint32_t DigestSize()
    {
        if (!inited_) {
            CCSEC_LOG_ERROR("DigestSize|END|returnF|Hash is not inited");
            return 0;
        }
        return digestSize_;
    }

    bool Reset()
    {
        if (!inited_) {
            CCSEC_LOG_ERROR("Reset|END|returnF|Hash is not inited");
            return false;
        }
#ifdef CDF_ENABLE_BLAKE3
        if (blake3Hasher_ != nullptr) {
            blake3_hasher_reset(blake3Hasher_.get());
            return true;
        }
#endif
        EVP_MD_CTX_reset(context_.get());
        auto res = EVP_DigestInit_ex(context_.get(), md_.get(), nullptr);
        if (res != OpenSSLRC::OK) { // 返回失败
            CCSEC_LOG_ERROR("Reset|END|returnF|EVP_DigestInit_ex false");
            return false;
        }

        return true;
    }

    bool Update(std::string_view input)
    {
        if (!inited_) {
            CCSEC_LOG_ERROR("Update|END|returnF|Hash is not inited");
            return false;
        }
        if (input.empty()) {
            CCSEC_LOG_ERROR("Update|END|returnF|invalid param, input is empty");
            return false;
        }
#ifdef CDF_ENABLE_BLAKE3
        if (blake3Hasher_ != nullptr) {
            blake3_hasher_update(blake3Hasher_.get(), input.data(), input.length());
            return true;
        }
#endif
        // 输入待计算数据，该接口在init后final前可以调用多次。
        const int32_t ret = EVP_DigestUpdate(context_.get(), input.data(), input.length());
        if (ret != OpenSSLRC::OK) {
            CCSEC_LOG_ERROR("Update|END|returnF|Failed to EVP_DigestUpdate, error code:" << ret);
            return false;
        }
        return true;
    }

    bool Finalize(std::vector<char> &output)
    {
        if (!inited_) {
            CCSEC_LOG_ERROR("Finalize|END|returnF|Hash is not inited");
            return false;
        }

#ifdef CDF_ENABLE_BLAKE3
        if (blake3Hasher_ != nullptr) {
            std::array<uint8_t, BLAKE3_OUT_LEN> digest{};
            blake3_hasher_finalize(blake3Hasher_.get(), digest.data(), digest.size());
            output.insert(output.end(), digest.begin(), digest.end());
            return true;
        }
#endif
        uint8_t *outputArray = (uint8_t *)malloc(digestSize_); // 输出buffer，由用户负责管理
        if (outputArray == nullptr) {
            CCSEC_LOG_ERROR("Finalize|END|returnF|Failed to malloc");
            return false;
        }
        // 获取哈希计算结果，结果储存到output里，outLen如果不等于哈希长度则会被设置为哈希长度
        int32_t ret = EVP_DigestFinal_ex(context_.get(), outputArray, &digestSize_);
        if (ret != OpenSSLRC::OK) {
            CCSEC_LOG_ERROR("Finalize|END|returnF|EVP_DigestFinal_ex, error code:" << ret);
            free(outputArray);
            outputArray = nullptr;
            return false;
        }

        output.insert(output.end(), outputArray, outputArray + digestSize_);
        free(outputArray);
        outputArray = nullptr;

        return true;
    }

private:
    uint32_t digestSize_ = 0; // 算法摘要长度
    bool inited_ = false; // 是否初始化成功

    ossl::UniqueMd md_;
    ossl::UniqueMdCtx context_; // 哈希上下文
#ifdef CDF_ENABLE_BLAKE3
    std::unique_ptr<blake3_hasher> blake3Hasher_;
#endif
};

Hash::Hash(HashAlgorithm algorithm) : impl_(std::make_unique<Impl>(algorithm)) {}

Hash::~Hash() = default; // 由于使用了unique_ptr，所以析构函数可以自动生成

uint32_t Hash::DigestSize()
{
    return impl_->DigestSize();
}

bool Hash::Reset()
{
    return impl_->Reset();
}

bool Hash::Update(std::string_view input)
{
    return impl_->Update(input);
}

bool Hash::Finalize(std::vector<char> &output)
{
    return impl_->Finalize(output);
}

bool HashStream(std::istream &input, HashAlgorithm algorithm, std::vector<char> &output)
{
    Hash hash(algorithm);
    if (hash.DigestSize() == 0) {
        CCSEC_LOG_ERROR("HashStream|END|returnF|invalid hash algorithm");
        return false;
    }

    std::array<char, HASH_STREAM_BUFFER_SIZE> buffer{};
    bool hasInput = false;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto bytesRead = input.gcount();
        if (bytesRead <= 0) {
            continue;
        }

        hasInput = true;
        if (!hash.Update(std::string_view(buffer.data(), static_cast<size_t>(bytesRead)))) {
            CCSEC_LOG_ERROR("HashStream|END|returnF|Failed to update");
            return false;
        }
    }

    if (input.bad() || (input.fail() && !input.eof())) {
        CCSEC_LOG_ERROR("HashStream|END|returnF|Failed to read input stream");
        return false;
    }
    if (!hasInput) {
        CCSEC_LOG_ERROR("HashStream|END|returnF|input is empty");
        return false;
    }
    if (!hash.Finalize(output)) {
        CCSEC_LOG_ERROR("HashStream|END|returnF|Failed to Finalize");
        return false;
    }
    return true;
}

bool Sha256Stream(std::istream &input, std::vector<char> &output)
{
    return HashStream(input, HashAlgorithm::SHA256, output);
}

bool Sha256(std::string_view input, std::vector<char> &output)
{
    if (input.empty()) {
        CCSEC_LOG_ERROR("Sha256|END|returnF|invalid param");
        return false;
    }

    Hash hash(HashAlgorithm::SHA256);

    auto ret = hash.Update(input);
    if (!ret) {
        CCSEC_LOG_ERROR("Sha256|END|returnF|Failed to update");
        return false;
    }

    ret = hash.Finalize(output);
    if (!ret) {
        CCSEC_LOG_ERROR("Sha256|END|returnF|Failed to Finalize");
        return false;
    }

    return true;
}
}
