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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iomanip> // 用于 std::setw 和 std::setfill
#include <iostream>
#include <iterator> // 用于 std::begin 和 std::end

#include "securec/securec.h"
#include "cdf/base/ccsec_logger.h"
#include "hash.h"

#include "ossl_wrappers.h"

namespace cdf {
class Hash::Impl {
public:
    explicit Impl(HashAlgorithm algorithm)
    {
        // check algorithm is valid
        if (algorithm == HashAlgorithm::UNKNOWN) {
            CCSEC_LOG_ERROR("Hash|END|returnF|Invalid hash algorithm");
            return;
        }

        // allocate algorithm
        switch (algorithm) {
            case HashAlgorithm::SHA256:
                // 获取openssl算法描述结构EVP_MD
                hash_algo_str = "sha2-256";
                md_ = ossl::FetchEvpMd(hash_algo_str);
                if (md_ == nullptr) {
                    CCSEC_LOG_ERROR("Hash|END|returnF|unsupported hash algorithm");
                    return;
                }
                break;
            default:
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
        EVP_MD_CTX_reset(context_.get());
        ossl::UniqueMd md = ossl::FetchEvpMd(hash_algo_str);
        if (md == nullptr) {
            CCSEC_LOG_ERROR("Reset|END|returnF|EVP_MD_fetch false");
            return false;
        }
        auto res = EVP_DigestInit_ex(context_.get(), md.get(), nullptr);
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
        if (input.length() > 0xffffffff) {
            CCSEC_LOG_ERROR("Update|END|returnF|invalid param, input is too long");
            return false;
        }
        uint8_t *data = new (std::nothrow) uint8_t[input.length()];
        if (data == nullptr) {
            CCSEC_LOG_ERROR("Update|END|returnF|Failed to allocate memory");
            return false;
        }
        int32_t ret = memcpy_s(data, input.length(), input.data(), input.length());
        if (ret != 0) {
            CCSEC_LOG_ERROR("Update|END|returnF|Failed to memcpy_s");
            delete[] data;
            data = nullptr;
            return false;
        }
        // 输入待计算数据，该接口在init后final前可以调用多次。
        ret = EVP_DigestUpdate(context_.get(), data, input.length());
        if (ret != OpenSSLRC::OK) {
            CCSEC_LOG_ERROR("Update|END|returnF|Failed to EVP_DigestUpdate, error code:" << ret);
            delete[] data;
            data = nullptr;
            return false;
        }
        delete[] data;
        data = nullptr;
        return true;
    }

    bool Finalize(std::vector<char> &output)
    {
        if (!inited_) {
            CCSEC_LOG_ERROR("Finalize|END|returnF|Hash is not inited");
            return false;
        }

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

    std::string hash_algo_str;
    ossl::UniqueMd md_;
    ossl::UniqueMdCtx context_; // 哈希上下文
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