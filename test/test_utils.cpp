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

#include "test_utils.h"

#include <iostream>

#include "gtest/gtest.h"

namespace cdf::test {
using namespace cdf;

void EnsureKmUninited(KeyManager *km)
{
    if (km->CheckInited()) {
        auto rc = km->UnInit();
        ASSERT_EQ(rc, KeyManagerRC::OK);
    }
}

void EnsureKmUninited(KeyManagerTy type)
{
    auto *km = KeyManagerFactory::Borrow(type);
    EnsureKmUninited(km);
}

void SetExternalLogCallBack(int level, const char *msg)
{
    std::cout << "|level:|" << level << " |msg: " << msg << std::endl;
}

std::pair<KeyManagerRC, std::string> StubRunCommandAndGetResult([[maybe_unused]] std::string_view exePath,
                                                                [[maybe_unused]] std::string_view accessToken,
                                                                [[maybe_unused]] std::string_view cmdArgs)
{
    return {KeyManagerRC::OK, ""};
}

KeyManagerRC StubGetJsonFieldIntPairVec([[maybe_unused]] const std::string &jsonStr,
                                        [[maybe_unused]] std::vector<std::pair<uint32_t, uint32_t>> &out)
{
    return KeyManagerRC::OK;
}

int StubGetJsonFieldMaxInt([[maybe_unused]] const std::string &jsonStr)
{
    return 0;
}

std::string StubGetOpenbaoLastKeyAsStr([[maybe_unused]] const std::string &readResultStr)
{
    return "test";
}

std::pair<KeyManagerRC, std::vector<std::byte>> StubEncryptOpenbao([[maybe_unused]] const CryptoSymAlg &symAlg,
                                                                   [[maybe_unused]] uint32_t domainId,
                                                                   [[maybe_unused]] std::string_view plaintext)
{
    std::vector<std::byte> vec(DEFAULT_VEC_SIZE);
    return {KeyManagerRC::OK, vec};
}

std::pair<KeyManagerRC, std::vector<std::byte>> StubDecryptOpenbao([[maybe_unused]] const CryptoSymAlg &alg,
                                                                   [[maybe_unused]] uint32_t domainId,
                                                                   [[maybe_unused]] std::string_view ciphertext)
{
    std::vector<std::byte> vec(DEFAULT_VEC_SIZE);
    return {KeyManagerRC::OK, vec};
}
} // namespace cdf::test
