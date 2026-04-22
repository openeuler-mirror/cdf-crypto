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

#include <unistd.h>

#include <algorithm>
#include <climits>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// Make cleancode happy
// clang-format off
#include "gtest/gtest.h"
#include "securec.h"
#include "stub.h"
#include "test_utils.h"
// clang-format on

#include <krb5/krb5.h>

#include "openssl/evp.h"

#include "cdf/base/custom_logger.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/cryption/hash.h"
#include "cdf/modules/cryption/hmac.h"
#include "cdf/modules/cryption/km_cryptor.h"
#include "cdf/modules/cryption/native_cryptor.h"
#include "cdf/modules/cryption/native_cryptor_engine.h"
#include "cdf/modules/key_management/define.h"
#include "cdf/modules/key_management/key_manager.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/key_management/openbao/openbao_key_manager.h"
#include "cdf/modules/key_management/openbao/openbao_utils.h"
#include "cdf/modules/rand/rand.h"

namespace cdf::test {
constexpr static auto SIZE = 1024 * 1024;

class KmCryptorTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        EXPECT_TRUE(Logger::Instance()->SetExternalLogFunction(SetExternalLogCallBack));
    }
};

class TestCrypto : public ::testing::Test {
protected:
    void SetUp() override
    {
        EXPECT_TRUE(Logger::Instance()->SetExternalLogFunction(SetExternalLogCallBack));
    }
};

namespace {

constexpr std::string_view TEST_PLAINTEXT = "1";

const std::string KM_EXEPATH = "./";
const std::string KM_ACCESSTOKEN = "testToken";

constexpr int DEFAULT_DOMAIN_COUNT = 2;

const std::string DEFAULT_KSF_BACKUP = std::filesystem::current_path().string() + "/ksf_backup";

inline std::string VecByteToString(std::vector<std::byte> in)
{
    return {reinterpret_cast<char *>(in.data()), in.size()};
}

inline void KmcOperation(int userId, KeyManager *km)
{
    const int defaultIteratonNum = 3000;
    auto cryptor = KmCryptor(km);
    for (int i = 0; i < defaultIteratonNum; ++i) {
        auto ret = cryptor.Encrypt(CryptoSymAlg::AES256_GCM, "1111111111", 0);
        ASSERT_EQ((int)ret.first, (int)CryptionRC::OK);
        ret = cryptor.Decrypt(CryptoSymAlg::AES256_GCM, ret.second, 0);
        ASSERT_TRUE(ret.first == CryptionRC::OK);
        ASSERT_EQ(VecByteToString(ret.second), "1111111111");
        if (userId == 1) {
            std::cout << "User " << userId << " complete " << i << std::endl;
        }
    }
}

} // namespace

bool StubUpdateError([[maybe_unused]] std::string_view input)
{
    return false;
}

bool StubFinalizeError([[maybe_unused]] std::vector<char> &output)
{
    return false;
}

EVP_MD_CTX *StubEvpMdCtxNewError()
{
    return nullptr;
}

TEST_F(TestCrypto, NativeCryptor_Encrypt_Decrypt_ParamAlg)
{
    NativeCryptor cryptor;
    std::vector<std::byte> plaintext;
    std::vector<std::byte> key;
    //    EXPECT_EQ(InitLog(static_cast<int>(LogLevel::LOG_LEVEL_INFO)), LogRc::SUCCESS);
    auto ret = cryptor.Encrypt(CryptoSymAlg::UNKNOWN, plaintext, key);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    ret = cryptor.Decrypt(CryptoSymAlg::UNKNOWN, plaintext, key);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    plaintext.push_back(std::byte{1});
    std::vector<std::byte> key1(32, std::byte{0}); // 32
    std::vector<std::byte> key2(16, std::byte{0}); // 16

    ret = cryptor.Encrypt(CryptoSymAlg::AES256_GCM, plaintext, key1);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES256_GCM, ret.second, key1);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    for (size_t i = 0; i < ret.second.size(); ++i) {
        EXPECT_EQ(plaintext[i], (ret.second)[i]);
    }

    ret = cryptor.Encrypt(CryptoSymAlg::CHACHA20_POLY1305, plaintext, key1);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::CHACHA20_POLY1305, ret.second, key1);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    ret = cryptor.Encrypt(CryptoSymAlg::AES128_CCM, plaintext, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_CCM, ret.second, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    ret = cryptor.Encrypt(CryptoSymAlg::SM4_CTR, plaintext, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::SM4_CTR, ret.second, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());
    memset_s(key.data(), key.size(), 0, key.size());
}

TEST_F(TestCrypto, NativeCryptor_Encrypt_Decrypt_ParamPlaintext)
{
    NativeCryptor cryptor;
    std::vector<std::byte> key(16, std::byte{0}); // 16
    std::vector<std::byte> plaintext1;
    auto ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext1, key);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, plaintext1, key);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    plaintext1.push_back(std::byte{1});
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext1, key);
    memset_s(plaintext1.data(), plaintext1.size(), 0, plaintext1.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> plaintext2;
    plaintext2.push_back(std::byte{'a'});
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext2, key);
    memset_s(plaintext2.data(), plaintext2.size(), 0, plaintext2.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> plaintext3;
    plaintext3.push_back(std::byte{'.'});
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext3, key);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext3, key);
    memset_s(plaintext3.data(), plaintext3.size(), 0, plaintext3.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    std::vector<std::byte> errorText;
    errorText.push_back(std::byte{123});
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, errorText, key);
    EXPECT_EQ(ret.first, CryptionRC::ERROR);

    std::vector<std::byte> plaintext4;
    plaintext4.resize(SIZE);
    std::generate(plaintext4.begin(), plaintext4.end(),
                  []() { return std::byte{static_cast<unsigned char>(std::rand())}; });
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext4, key);
    memset_s(plaintext4.data(), plaintext4.size(), 0, plaintext4.size());
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
}

TEST_F(TestCrypto, NativeCryptor_Encrypt_Decrypt_ParamLongPlaintext)
{
    NativeCryptor cryptor;
    std::vector<std::byte> key(16, std::byte{0}); // 16
    std::vector<std::byte> plaintext5;
    plaintext5.resize(SIZE - 1);
    std::generate(plaintext5.begin(), plaintext5.end(),
                  []() { return std::byte{static_cast<unsigned char>(std::rand())}; });
    auto ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext5, key);
    memset_s(plaintext5.data(), plaintext5.size(), 0, plaintext5.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> key2(32, std::byte{0}); // 32
    std::vector<std::byte> plaintext6;
    plaintext6.resize(SIZE - 1);
    std::generate(plaintext6.begin(), plaintext6.end(),
                  []() { return std::byte{static_cast<unsigned char>(std::rand())}; });
    ret = cryptor.Encrypt(CryptoSymAlg::AES256_GCM, plaintext6, key2);
    memset_s(plaintext6.data(), plaintext6.size(), 0, plaintext6.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES256_GCM, ret.second, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> plaintext7;
    plaintext7.resize(SIZE - 1);
    std::generate(plaintext7.begin(), plaintext7.end(),
                  []() { return std::byte{static_cast<unsigned char>(std::rand())}; });
    ret = cryptor.Encrypt(CryptoSymAlg::SM4_CTR, plaintext7, key);
    memset_s(plaintext7.data(), plaintext7.size(), 0, plaintext7.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::SM4_CTR, ret.second, key);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> plaintext8;
    plaintext8.resize(SIZE - 1);
    std::generate(plaintext8.begin(), plaintext8.end(),
                  []() { return std::byte{static_cast<unsigned char>(std::rand())}; });
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_CCM, plaintext8, key);
    memset_s(plaintext8.data(), plaintext8.size(), 0, plaintext8.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_CCM, ret.second, key);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> plaintext9;
    plaintext9.resize(SIZE - 1);
    std::generate(plaintext9.begin(), plaintext9.end(),
                  []() { return std::byte{static_cast<unsigned char>(std::rand())}; });
    ret = cryptor.Encrypt(CryptoSymAlg::CHACHA20_POLY1305, plaintext9, key2);
    memset_s(plaintext9.data(), plaintext9.size(), 0, plaintext9.size());
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::CHACHA20_POLY1305, ret.second, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);
}

TEST_F(TestCrypto, NativeCryptor_Encrypt_Decrypt_ParamKey)
{
    NativeCryptor cryptor;
    std::vector<std::byte> plaintext;
    plaintext.push_back(std::byte{123});
    std::vector<std::byte> key1;
    auto ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext, key1);
    memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, plaintext, key1);
    EXPECT_EQ(ret.first, CryptionRC::INVALID_PARAM);

    std::vector<std::byte> key2(16, std::byte{0}); // 16
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key2);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> key3(16, std::byte{'a'}); // 16
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext, key3);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key3);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> key4(16, std::byte{'.'}); // 16
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext, key4);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key4);
    EXPECT_EQ(ret.first, CryptionRC::OK);

    std::vector<std::byte> key5(6, std::byte{'.'}); // 6
    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext, key5);
    EXPECT_EQ(ret.first, CryptionRC::ERROR);

    ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, plaintext, key3);
    EXPECT_EQ(ret.first, CryptionRC::OK);
    ret = cryptor.Decrypt(CryptoSymAlg::AES128_GCM, ret.second, key2);
    EXPECT_EQ(ret.first, CryptionRC::ERROR);

    memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());
}

TEST_F(TestCrypto, NativeCryptor_KeyEncrypt_NUll)
{
    const uint8_t *cryptoKey = nullptr;
    const uint32_t cryptoKeyLen = 0;
    const uint8_t *plainText = nullptr;
    const uint32_t plainTextLen = 0;
    uint8_t *cipherText = nullptr;
    uint32_t *cipherTextLen = nullptr;
    auto result = KeyDecrypt(cryptoKey, cryptoKeyLen, plainText, plainTextLen, cipherText, cipherTextLen);
    EXPECT_EQ(result, CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
}

TEST_F(TestCrypto, Pbkdf2HmacParam_TEST)
{
    char testStr[] = "23134143nsjahed2qu";
    // 使用字符数组初始化std::vector<uint8_t>
    std::vector<uint8_t> pwdVector(testStr, testStr + std::strlen(testStr));
    Pbkdf2ConfigStruct pbkdf2ConfigStruct;
    std::vector<uint8_t> out;
    // 算法id
    pbkdf2ConfigStruct.ccsecCryptMacAlgId = static_cast<CcsecCryptMacAlgId>(99); // 99
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_PARAM_INVALID);
    // 迭代次数 先恢复正常算法id
    pbkdf2ConfigStruct.ccsecCryptMacAlgId = CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA256;
    pbkdf2ConfigStruct.iterationTimes = PBKDF2_ITERATION_TIMES_MIN - 1;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_PARAM_INVALID);
    pbkdf2ConfigStruct.iterationTimes = PBKDF2_ITERATION_TIMES_MAX + 1;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_PARAM_INVALID);
    // outLen 先恢复正常迭代次数
    pbkdf2ConfigStruct.iterationTimes = PBKDF2_ITERATION_TIMES_DEFAULT;
    pbkdf2ConfigStruct.outLen = PBKDF2_OUT_LEN_MIN - 1;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_PARAM_INVALID);
    pbkdf2ConfigStruct.outLen = PBKDF2_OUT_LEN_MAX + 1;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_PARAM_INVALID);
    // 盐值长度 先恢复正常outLen
    pbkdf2ConfigStruct.outLen = PBKDF2_OUT_LEN_DEFAULT;
    std::vector<uint8_t> salt;
    salt.resize(PBKDF2_SALT_LEN_MIN - 1);
    pbkdf2ConfigStruct.salt = salt;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_PARAM_INVALID);
    salt.resize(PBKDF2_SALT_LEN_MIN + 1);
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_PARAM_INVALID);
}

TEST_F(TestCrypto, Pbkdf2Hmac_TEST)
{
    char testStr[] = "23134143nsjahed2qu";
    // 使用字符数组初始化std::vector<uint8_t>
    std::vector<uint8_t> pwdVector(testStr, testStr + std::strlen(testStr));
    std::vector<uint8_t> salt;
    uint32_t saltLen = 16;
    salt.resize(saltLen);
    Pbkdf2ConfigStruct pbkdf2ConfigStruct;
    int32_t ret = GetRand(salt.data(), salt.size());
    EXPECT_TRUE(ret == CCSEC_CRYPT_OK);
    pbkdf2ConfigStruct.salt = salt;
    std::vector<uint8_t> out;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_OK);

    std::vector<uint8_t> out2;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out2) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out2 == out);
    std::string outBase64Str(out.begin(), out.end());
    // 输出字符串
    std::cout << "Base64 encoded string: " << outBase64Str << std::endl;
    Pbkdf2ConfigStruct pbkdf2ConfigStruct2;
    pbkdf2ConfigStruct2.salt = salt;
    char testStr2[] = "a";
    std::vector<uint8_t> shortValue(testStr2, testStr2 + std::strlen(testStr2));
    std::string shortString = "d";
    EXPECT_TRUE(GetPbkdf2Config(shortValue, pbkdf2ConfigStruct2) == CcsecCryptErrorCode::CCSEC_CRYPT_PARAM_INVALID);
    EXPECT_TRUE(GetPbkdf2Config(out, pbkdf2ConfigStruct2) == CCSEC_CRYPT_OK);
    std::vector<uint8_t> reOut;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct2, reOut) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out == reOut);

    // id不同
    std::vector<uint8_t> out4;
    pbkdf2ConfigStruct2.ccsecCryptMacAlgId = CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA384;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct2, out4) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out != out4);
    // 迭代次数不同
    pbkdf2ConfigStruct2.ccsecCryptMacAlgId = CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA256;
    pbkdf2ConfigStruct2.iterationTimes = 10251; // 10251
    std::vector<uint8_t> out3;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct2, out3) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out != out3);
    memset_s(testStr, strlen(testStr), 0, strlen(testStr));
    memset_s(testStr2, strlen(testStr2), 0, strlen(testStr2));
}

TEST_F(TestCrypto, Secure_PBKDF2_Interface_Para_Verification_11)
{
    char testStr[] = "1234567890";
    std::vector<uint8_t> pwdVector(testStr, testStr + std::strlen(testStr));
    std::vector<uint8_t> salt;
    uint32_t saltLen = 16;
    salt.resize(saltLen);
    Pbkdf2ConfigStruct pbkdf2ConfigStruct;
    pbkdf2ConfigStruct.salt = salt;
    std::vector<uint8_t> out;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_OK);

    std::vector<uint8_t> out2;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out2) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out == out2);

    std::vector<uint8_t> out3;
    pbkdf2ConfigStruct.ccsecCryptMacAlgId = CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA384;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out3) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out != out3);
    memset_s(testStr, strlen(testStr), 0, strlen(testStr));
}

TEST_F(TestCrypto, Secure_PBKDF2_Interface_Para_Verification_12)
{
    char testStr[] = "1234567890";
    std::vector<uint8_t> pwdVector(testStr, testStr + std::strlen(testStr));
    std::vector<uint8_t> salt;
    uint32_t saltLen = 16;
    salt.resize(saltLen);
    Pbkdf2ConfigStruct pbkdf2ConfigStruct;
    pbkdf2ConfigStruct.salt = salt;
    std::vector<uint8_t> out;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out) == CCSEC_CRYPT_OK);

    std::vector<uint8_t> out2;
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out2) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out == out2);

    std::vector<uint8_t> out3;
    pbkdf2ConfigStruct.iterationTimes = 10251; // 10251
    EXPECT_TRUE(Pbkdf2Hmac(pwdVector, pbkdf2ConfigStruct, out3) == CCSEC_CRYPT_OK);
    EXPECT_TRUE(out != out3);
    memset_s(testStr, strlen(testStr), 0, strlen(testStr));
}

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

    // 创建16个用户线程
    const int numUsers = 16;
    threads.reserve(numUsers);
    for (int i = 0; i < numUsers; ++i) {
        threads.emplace_back(KmcOperation, i, km);
    }

    // 等待所有线程完成
    for (auto &thread : threads) {
        thread.join();
    }

    km->UnInit();
}

TEST_F(KmCryptorTest, UNINIT_TEST)
{
    auto *km = KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    auto cryptor = KmCryptor(km);
    km->UnInit();
    auto ret = cryptor.Encrypt(CryptoSymAlg::AES128_GCM, "123213", 0);
    EXPECT_EQ(ret.first, CryptionRC::UNINITED);
}

TEST_F(KmCryptorTest, Sha256Success)
{
    std::string_view str;
    std::vector<char> output1;
    auto ret = Sha256(str, output1);
    EXPECT_EQ(ret, false);
    str = "1234";
    ret = Sha256(str, output1);
    str = "abc";
    std::vector<char> output2;
    ret = Sha256(str, output2);
    EXPECT_EQ(ret, true);
    std::vector<char> output3;
    ret = Sha256(str, output3);
    EXPECT_EQ(ret, true);
    std::string vecStr = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    std::vector<char> vec;
    int number = 2;
    for (size_t i = 0; i < vecStr.length(); i += number) {
        std::string byteString = vecStr.substr(i, number);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        vec.push_back(byte);
    }
    EXPECT_EQ(output3, vec);
}

TEST_F(KmCryptorTest, Sha256UpdateError)
{
    std::string_view str = "1234";
    Stub stub;
    stub.Set(Hash::Update, StubUpdateError);
    std::vector<char> output;
    auto ret = Sha256(str, output);
    EXPECT_EQ(ret, false);
    stub.Reset(Hash::Update);
}

TEST_F(KmCryptorTest, Sha256FinalizeError)
{
    std::string_view str = "1234";
    Stub stub;
    stub.Set(Hash::Finalize, StubFinalizeError);
    std::vector<char> output;
    auto ret = Sha256(str, output);
    EXPECT_EQ(ret, false);
    stub.Reset(Hash::Finalize);
}

TEST_F(KmCryptorTest, Hash_Hash)
{
    Hash hash1(HashAlgorithm::UNKNOWN);
    std::string_view str = "test";
    auto ret = hash1.Update(str);
    EXPECT_EQ(ret, false);
    Hash hash2(HashAlgorithm::SHA512);
    ret = hash2.Update(str);
    EXPECT_EQ(ret, false);
    std::vector<char> output;
    ret = hash2.Finalize(output);
    EXPECT_EQ(ret, false);
    Hash hash3(HashAlgorithm::SHA256);
    uint32_t digestSize = 256 / 8;
    EXPECT_EQ(hash3.DigestSize(), digestSize);
    ret = hash3.Update(str);
    EXPECT_EQ(ret, true);
}

TEST_F(KmCryptorTest, Hash_MdNewCtxError)
{
    Stub stub;
    stub.Set(EVP_MD_CTX_new, StubEvpMdCtxNewError);
    Hash hash(HashAlgorithm::SHA256);
    std::string_view str = "test";
    auto ret = hash.Update(str);
    EXPECT_EQ(ret, false);
    stub.Reset(EVP_MD_CTX_new);
}

} // namespace cdf::test
