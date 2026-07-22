/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 */

#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

#include "cdf/base/custom_logger.h"
#include "cdf/modules/key_management/key_manager.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/key_management/km_cryptor.h"
#include "test_utils.h"

namespace cdf::test {

class KmCryptorTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        EXPECT_TRUE(Logger::Instance()->SetExternalLogFunction(SetExternalLogCallBack));
    }
};

namespace {

std::string VecByteToString(std::vector<std::byte> input)
{
    return {reinterpret_cast<char *>(input.data()), input.size()};
}

void KmcOperation(int userId, KeyManager *km)
{
    constexpr int DEFAULT_ITERATION_COUNT = 3000;
    auto cryptor = KmCryptor(km);
    for (int i = 0; i < DEFAULT_ITERATION_COUNT; ++i) {
        auto ret = cryptor.Encrypt(CryptoSymAlg::AES256_GCM, "1111111111", 0);
        ASSERT_EQ(ret.first, CryptionRC::OK);
        ret = cryptor.Decrypt(CryptoSymAlg::AES256_GCM, ret.second, 0);
        ASSERT_EQ(ret.first, CryptionRC::OK);
        ASSERT_EQ(VecByteToString(ret.second), "1111111111");
        if (userId == 1) {
            std::cout << "User " << userId << " complete " << i << std::endl;
        }
    }
}

} // namespace

TEST_F(KmCryptorTest, DISABLED_PERFORMANCE_TEST)
{
    std::vector<std::thread> threads;
    auto *km = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    if (km->CheckInited()) {
        km->UnInit();
    }

    auto rc = km->Init("/bin/bao", "xxxxxxxxxxxxxxxxxxxxxx", 2);
    ASSERT_EQ(rc, KeyManagerRC::OK);
    ASSERT_EQ(km->CreateKey(0).first, KeyManagerRC::OK);

    constexpr int USER_COUNT = 16;
    threads.reserve(USER_COUNT);
    for (int i = 0; i < USER_COUNT; ++i) {
        threads.emplace_back(KmcOperation, i, km);
    }
    for (auto &thread : threads) {
        thread.join();
    }

    km->UnInit();
}

TEST_F(KmCryptorTest, UninitializedKeyManager)
{
    auto *km = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto cryptor = KmCryptor(km);
    km->UnInit();
    auto ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, "123213", 0);
    EXPECT_EQ(ret.first, CryptionRC::UNINITED);
}

} // namespace cdf::test
