/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
          * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <filesystem>
#include <iostream>
#include <string>

#include "gtest/gtest.h"
#include "stub.h"
#include "test_utils.h"

#include "cdf/modules/key_management/km_cryptor.h"
#include "cdf/modules/cryption/native_cryptor.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/key_management/openbao/openbao_key_manager.h"
#include "cdf/modules/key_management/openbao/openbao_utils.h"
#include "cdf/modules/key_management/vault/vault_key_manager.h"

namespace cdf::test {
namespace {
constexpr int MAX_ROOT_KEY_VALID_TIME = 30 * 365;
constexpr int MAX_MASTER_KEY_VALID_TIME = 180;

// External C interface declarations
extern "C" {
cdf::OpenbaoKeyManager *BorrowOpenbaoKeyManager();
cdf::VaultKeyManager *BorrowVaultKeyManager();
}

} // namespace

class KeyManagerTest : public ::testing::Test {};

class KeyManagerVaultTest : public ::testing::Test {};

class KeyManagerOpenbaoTest : public ::testing::Test {};

void TestLogFunc(int level, const char *msg)
{
    std::cout << "|Test log print|level:" << level << " msg:" << msg << std::endl;
}

KeyManagerRC StubRunCommandAndCheckError([[maybe_unused]] std::string_view exePath,
                                         [[maybe_unused]] std::string_view accessToken,
                                         [[maybe_unused]] std::vector<char *> &cmdVec,
                                         [[maybe_unused]] std::string commandKey)
{
    return KeyManagerRC::ERROR;
}

KeyManagerRC StubRunCommandAndCheck([[maybe_unused]] std::string_view exePath,
                                    [[maybe_unused]] std::string_view accessToken,
                                    [[maybe_unused]] std::vector<char *> &cmdVec,
                                    [[maybe_unused]] std::string commandKey)
{
    return KeyManagerRC::OK;
}

std::string StubGetOpenbaoLastKeyAsStrError([[maybe_unused]] const std::string &readResultStr)
{
    return "";
}

std::pair<CryptionRC, std::vector<std::byte>> StubEncrypt([[maybe_unused]] const CryptoSymAlg &alg,
                                                          [[maybe_unused]] std::vector<std::byte> &plaintext,
                                                          [[maybe_unused]] std::vector<std::byte> &key)
{
    std::vector<std::byte> vec;
    vec.push_back(std::byte(0));
    return {CryptionRC::OK, vec};
}

std::pair<CryptionRC, std::vector<std::byte>> StubEncryptError([[maybe_unused]] const CryptoSymAlg &alg,
                                                               [[maybe_unused]] std::vector<std::byte> &plaintext,
                                                               [[maybe_unused]] std::vector<std::byte> &key)
{
    return {CryptionRC::ERROR, {}};
}

std::pair<CryptionRC, std::vector<std::byte>> StubDecrypt([[maybe_unused]] const CryptoSymAlg &alg,
                                                          [[maybe_unused]] std::vector<std::byte> &ciphertext,
                                                          [[maybe_unused]] std::vector<std::byte> &key)
{
    std::vector<std::byte> vec;
    vec.push_back(std::byte(0));
    return {CryptionRC::OK, vec};
}

std::pair<CryptionRC, std::vector<std::byte>> StubDecryptError([[maybe_unused]] const CryptoSymAlg &alg,
                                                               [[maybe_unused]] std::vector<std::byte> &ciphertext,
                                                               [[maybe_unused]] std::vector<std::byte> &key)
{
    return {CryptionRC::ERROR, {}};
}

TEST_F(KeyManagerOpenbaoTest, UnInit)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    KeyManagerTy type = Openbaokm->Type();
    EXPECT_EQ(type, KeyManagerTy::OPENBAO);
    uint32_t domainCount = Openbaokm->DomainCount();
    EXPECT_EQ(domainCount, static_cast<uint32_t>(2)); // 2
    bool isInit = Openbaokm->CheckInited();
    EXPECT_EQ(isInit, false);
    auto ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
}

TEST_F(KeyManagerOpenbaoTest, Init)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->Init("", "", -1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->Init("./", "", -1);
    EXPECT_EQ(ret, KeyManagerRC::DOMAIN_COUNT_INVALID);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "", 2);
    EXPECT_EQ(ret, KeyManagerRC::ERROR);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerOpenbaoTest, CreateKey_RunCommandAndCheckError)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::INVALID_PARAM);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheckError);
    ret = Openbaokm->CreateKey(0);
    EXPECT_EQ(ret.first, KeyManagerRC::ERROR);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    initRet = Openbaokm->UnInit();
    EXPECT_EQ(initRet, KeyManagerRC::OK);
}

TEST_F(KeyManagerOpenbaoTest, CreateKey_RunCommandAndCheck)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::INVALID_PARAM);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    ret = Openbaokm->CreateKey(0);
    EXPECT_EQ(ret.first, KeyManagerRC::OK);
    initRet = Openbaokm->RemoveKey(0, ret.second);
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
    initRet = Openbaokm->UnInit();
    EXPECT_EQ(initRet, KeyManagerRC::OK);
}

TEST_F(KeyManagerOpenbaoTest, RemoveKey)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->RemoveKey(-1, -1);
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->RemoveKey(-1, -1);
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = Openbaokm->RemoveKey(-1, -1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->RemoveKey(0, -1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
}

TEST_F(KeyManagerOpenbaoTest, DisplayAllKey)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->DisplayAllKey();
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->DisplayAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);
    ret = Openbaokm->DisplayAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerOpenbaoTest, DisplayKey)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->DisplayKey(-1);
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->DisplayKey(-1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->DisplayKey(0);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);
    ret = Openbaokm->DisplayKey(0);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerOpenbaoTest, DeleteAllKey)
{
    auto &km = OpenbaoKeyManager::GetInstance();
    auto ret = km.DeleteAllKey();
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    ret = km.Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = km.DeleteAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = km.DeleteAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = km.UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerOpenbaoTest, CheckDomainKeysExpired)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->CheckDomainKeysExpired(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->CheckDomainKeysExpired(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = Openbaokm->CheckDomainKeysExpired(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->CheckDomainKeysExpired(0, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerOpenbaoTest, CheckDomainKeysExpiredAndAutoUpdate)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(0, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerOpenbaoTest, Encrypt)
{
    auto &km = OpenbaoKeyManager::GetInstance();
    auto cryptor = KmCryptor(KeyManagerTy::OPENBAO);
    auto ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = km.Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    stub.Set(GetJsonFieldAsStr, StubGetOpenbaoLastKeyAsStr);
    stub.Set(NativeCryptor::Encrypt, StubEncrypt);
    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "test", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    auto result = km.DeleteAllKey();
    EXPECT_EQ(result, KeyManagerRC::OK);
    result = km.UnInit();
    EXPECT_EQ(result, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(GetJsonFieldAsStr);
    stub.Reset(NativeCryptor::Encrypt);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerOpenbaoTest, Decrypt)
{
    auto &km = OpenbaoKeyManager::GetInstance();
    auto cryptor = KmCryptor(KeyManagerTy::OPENBAO);
    auto ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = km.Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    stub.Set(GetJsonFieldAsStr, StubGetOpenbaoLastKeyAsStr);
    stub.Set(NativeCryptor::Decrypt, StubDecrypt);
    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "test", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    auto result = km.DeleteAllKey();
    EXPECT_EQ(result, KeyManagerRC::OK);
    result = km.UnInit();
    EXPECT_EQ(result, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(GetJsonFieldAsStr);
    stub.Reset(NativeCryptor::Decrypt);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, UnInit)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    KeyManagerTy type = Openbaokm->Type();
    EXPECT_EQ(type, KeyManagerTy::VAULT);
    uint32_t domainCount = Openbaokm->DomainCount();
    EXPECT_EQ(domainCount, static_cast<uint32_t>(2)); // 2
    bool isInit = Openbaokm->CheckInited();
    EXPECT_EQ(isInit, false);
    auto ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
}

TEST_F(KeyManagerVaultTest, Init)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->Init("", "", -1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->Init("./", "", -1);
    EXPECT_EQ(ret, KeyManagerRC::DOMAIN_COUNT_INVALID);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "", 2);
    EXPECT_EQ(ret, KeyManagerRC::ERROR);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, CreateKey_RunCommandAndCheckError)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::UNINITED);

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::INVALID_PARAM);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheckError);
    ret = Openbaokm->CreateKey(0);
    EXPECT_EQ(ret.first, KeyManagerRC::ERROR);
    stub.Reset(RunCommandAndCheck);

    initRet = Openbaokm->UnInit();
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, CreateKey_RunCommandAndCheck)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::UNINITED);

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = Openbaokm->CreateKey(-1);
    EXPECT_EQ(ret.first, KeyManagerRC::INVALID_PARAM);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    ret = Openbaokm->CreateKey(0);
    EXPECT_EQ(ret.first, KeyManagerRC::OK);
    initRet = Openbaokm->RemoveKey(0, ret.second);
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
    initRet = Openbaokm->UnInit();
    EXPECT_EQ(initRet, KeyManagerRC::OK);
}

TEST_F(KeyManagerVaultTest, RemoveKey)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->RemoveKey(-1, -1);
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->RemoveKey(-1, -1);
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = Openbaokm->RemoveKey(-1, -1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->RemoveKey(0, -1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
}

TEST_F(KeyManagerVaultTest, DisplayAllKey)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->DisplayAllKey();
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->DisplayAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);
    ret = Openbaokm->DisplayAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, DisplayKey)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->DisplayKey(-1);
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->DisplayKey(-1);
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->DisplayKey(0);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);
    ret = Openbaokm->DisplayKey(0);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, DeleteAllKey)
{
    auto &km = VaultKeyManager::GetInstance();
    auto ret = km.DeleteAllKey();
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = km.Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = km.DeleteAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = km.DeleteAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = km.UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, CheckDomainKeysExpired)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->CheckDomainKeysExpired(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->CheckDomainKeysExpired(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = Openbaokm->CheckDomainKeysExpired(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->CheckDomainKeysExpired(0, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, CheckDomainKeysExpiredAndAutoUpdate)
{
    auto *Openbaokm = KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    auto ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    ret = Openbaokm->Init("./", "test_token", 2); // 2
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    auto createRet = Openbaokm->CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(-1, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);

    ret = Openbaokm->CheckDomainKeysExpiredAndAutoUpdate(0, 6 * 365); // 6 * 365
    EXPECT_EQ(ret, KeyManagerRC::INVALID_PARAM);
    ret = Openbaokm->RemoveKey(0, createRet.second);
    EXPECT_EQ(ret, KeyManagerRC::OK);
    ret = Openbaokm->UnInit();
    EXPECT_EQ(ret, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, Encrypt)
{
    auto &km = VaultKeyManager::GetInstance();
    auto cryptor = KmCryptor(KeyManagerTy::VAULT);
    auto ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = km.Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    stub.Set(GetJsonFieldAsStr, StubGetOpenbaoLastKeyAsStr);
    stub.Set(NativeCryptor::Encrypt, StubEncrypt);
    ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, "test", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    auto result = km.DeleteAllKey();
    EXPECT_EQ(result, KeyManagerRC::OK);
    result = km.UnInit();
    EXPECT_EQ(result, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(GetJsonFieldAsStr);
    stub.Reset(NativeCryptor::Encrypt);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(KeyManagerVaultTest, Decrypt)
{
    auto &km = VaultKeyManager::GetInstance();
    auto cryptor = KmCryptor(KeyManagerTy::VAULT);
    auto ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::UNINITED);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    auto initRet = km.Init("./", "test_token", 2); // 2
    EXPECT_EQ(initRet, KeyManagerRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::ERROR);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", -1);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    stub.Set(GetJsonFieldAsStr, StubGetOpenbaoLastKeyAsStr);
    stub.Set(NativeCryptor::Decrypt, StubDecrypt);
    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, "test", 0);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    auto result = km.DeleteAllKey();
    EXPECT_EQ(result, KeyManagerRC::OK);
    result = km.UnInit();
    EXPECT_EQ(result, KeyManagerRC::OK);
    stub.Reset(RunCommandAndCheck);
    stub.Reset(GetJsonFieldAsStr);
    stub.Reset(NativeCryptor::Decrypt);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
}

// Test cases for openbao_utils JSON parsing functions
class OpenbaoUtilsTest : public ::testing::Test {};

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_ValidJson)
{
    // Valid JSON with string keys
    std::string jsonStr = R"({"data":{"keys":{"key1":"value1","key2":"value2"}}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_EQ(result, "value2"); // Returns the last element
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_InvalidJson)
{
    // Invalid JSON string
    std::string jsonStr = "invalid json";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_EmptyJson)
{
    // Empty JSON object
    std::string jsonStr = "{}";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_MissingDataField)
{
    // JSON missing "data" field
    std::string jsonStr = R"({"keys":{"key1":"value1"}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_MissingKeysField)
{
    // JSON missing "keys" field
    std::string jsonStr = R"({"data":{"other":"value"}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldAsStr_NonStringValue)
{
    // JSON with non-string value in keys
    std::string jsonStr = R"({"data":{"keys":{"key1":123}}})";
    auto result = GetJsonFieldAsStr(jsonStr);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_ValidJson)
{
    // Valid JSON with integer keys
    std::string jsonStr = R"({"data":{"keys":{"key1":1,"key2":5,"key3":3}}})";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, 5);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_InvalidJson)
{
    // Invalid JSON string
    std::string jsonStr = "invalid json";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, -1);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_EmptyJson)
{
    // Empty JSON object
    std::string jsonStr = "{}";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, -1);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_NonIntValue)
{
    // JSON with non-integer value
    std::string jsonStr = R"({"data":{"keys":{"key1":"not_an_int"}}})";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, -1);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldMaxInt_SingleValue)
{
    // JSON with single integer value
    std::string jsonStr = R"({"data":{"keys":{"key1":42}}})";
    auto result = GetJsonFieldMaxInt(jsonStr);
    EXPECT_EQ(result, 42);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_ValidJson)
{
    // Valid JSON array with domain_key format strings (CDF{domain}_Key{key_id})
    std::string jsonStr = R"(["CDF1_Key001","CDF1_Key002","CDF2_Key001"])";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::OK);
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0].first, 1u);
    EXPECT_EQ(result[0].second, 1u);
    EXPECT_EQ(result[1].first, 1u);
    EXPECT_EQ(result[1].second, 2u);
    EXPECT_EQ(result[2].first, 2u);
    EXPECT_EQ(result[2].second, 1u);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_InvalidJson)
{
    // Invalid JSON string
    std::string jsonStr = "invalid json";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
    EXPECT_TRUE(result.empty());
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_EmptyArray)
{
    // Empty JSON array
    std::string jsonStr = "[]";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_NotArray)
{
    // JSON is not an array
    std::string jsonStr = R"({"key":"value"})";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_InvalidFormat)
{
    // JSON with invalid domain_key format (wrong format causes parsing error)
    // StrDecodeToDomainIdKeyId returns -1 on parse error, causing ERROR return
    std::string jsonStr = R"(["invalid_format"])";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

TEST_F(OpenbaoUtilsTest, GetJsonFieldIntPairVec_NonStringElement)
{
    // JSON array with non-string element
    std::string jsonStr = R"([123, "CDF1_Key001"])";
    std::vector<std::pair<uint32_t, uint32_t>> result;
    auto rc = GetJsonFieldIntPairVec(jsonStr, result);
    EXPECT_EQ(rc, KeyManagerRC::ERROR);
}

// Test C interface functions for key manager
class KeyManagerCInterfaceTest : public ::testing::Test {};

TEST_F(KeyManagerCInterfaceTest, BorrowKeyManager_Openbao)
{
    auto *km = BorrowKeyManager(KeyManagerTy::OPENBAO);
    EXPECT_NE(km, nullptr);
    EXPECT_EQ(km->Type(), KeyManagerTy::OPENBAO);
    EXPECT_FALSE(km->CheckInited());
}

TEST_F(KeyManagerCInterfaceTest, BorrowKeyManager_Vault)
{
    auto *km = BorrowKeyManager(KeyManagerTy::VAULT);
    EXPECT_NE(km, nullptr);
    EXPECT_EQ(km->Type(), KeyManagerTy::VAULT);
    EXPECT_FALSE(km->CheckInited());
}

TEST_F(KeyManagerCInterfaceTest, BorrowOpenbaoKeyManager)
{
    auto *km = BorrowOpenbaoKeyManager();
    EXPECT_NE(km, nullptr);
    EXPECT_EQ(km->Type(), KeyManagerTy::OPENBAO);
    EXPECT_FALSE(km->CheckInited());
}

TEST_F(KeyManagerCInterfaceTest, BorrowVaultKeyManager)
{
    auto *km = BorrowVaultKeyManager();
    EXPECT_NE(km, nullptr);
    EXPECT_EQ(km->Type(), KeyManagerTy::VAULT);
    EXPECT_FALSE(km->CheckInited());
}

// Additional tests for error handling paths
class KeyManagerErrorHandlingTest : public ::testing::Test {
protected:
    Stub stub;
    void SetUp() override
    {
        stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
        stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
        stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    }
    void TearDown() override
    {
        stub.Reset(RunCommandAndGetResult);
        stub.Reset(GetJsonFieldMaxInt);
        stub.Reset(GetJsonFieldIntPairVec);
        stub.Reset(RunCommandAndCheck);
    }
};

TEST_F(KeyManagerErrorHandlingTest, CreateKey_RunCommandAndCheckFail)
{
    auto &km = OpenbaoKeyManager::GetInstance();
    auto ret = km.Init("./", "test_token", 2);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheckError);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::ERROR);

    km.UnInit();
}

TEST_F(KeyManagerErrorHandlingTest, PrepareMap_GetJsonFieldIntPairVecFail)
{
    auto &km = OpenbaoKeyManager::GetInstance();

    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVecError);
    auto ret = km.Init("./", "test_token", 2);
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    km.UnInit();
}

TEST_F(KeyManagerErrorHandlingTest, PrepareMap_GetJsonFieldMaxIntFail)
{
    auto &km = OpenbaoKeyManager::GetInstance();

    // Return non-empty result and data, then GetJsonFieldMaxInt fails
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResultWithData);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVecWithData);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxIntError);
    auto ret = km.Init("./", "test_token", 2);
    EXPECT_EQ(ret, KeyManagerRC::ERROR);

    km.UnInit();
}

TEST_F(KeyManagerErrorHandlingTest, RemoveKey_NonExistentKey)
{
    auto &km = OpenbaoKeyManager::GetInstance();
    auto ret = km.Init("./", "test_token", 2);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto removeRet = km.RemoveKey(0, 999);
    EXPECT_EQ(removeRet, KeyManagerRC::ERROR);

    km.UnInit();
}

TEST_F(KeyManagerErrorHandlingTest, DeleteAllKey_WithKeys)
{
    auto &km = OpenbaoKeyManager::GetInstance();
    auto ret = km.Init("./", "test_token", 2);
    EXPECT_EQ(ret, KeyManagerRC::OK);

    stub.Set(RunCommandAndCheck, StubRunCommandAndCheck);
    auto createRet = km.CreateKey(0);
    EXPECT_EQ(createRet.first, KeyManagerRC::OK);

    ret = km.DeleteAllKey();
    EXPECT_EQ(ret, KeyManagerRC::OK);

    km.UnInit();
}

} // namespace cdf::test
