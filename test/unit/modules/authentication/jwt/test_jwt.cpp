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

#include <unistd.h>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "stub.h"
#include "test_utils.h"
#include "cdf/modules/authentication/jwt/define.h"
#include "cdf/modules/authentication/jwt/jwt_auth_server.h"
#include "cdf/modules/authentication/jwt/option.h"
#include "cdf/modules/cryption/hmac.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/key_management/openbao/openbao_utils.h"
#include "cdf/modules/key_management/openbao/openbao_key_manager.h"
#include "cdf/modules/key_management/km_cryptor.h"

namespace cdf::test {

namespace {

constexpr int16_t DEFAULT_SERVER_KEY_EXPIRED_HOURS = 24;
constexpr int16_t DEFAULT_TOKEN_EXPIRE_MINUTES = 480;
constexpr int INVALID_CDF_DIST_AUTH_ALG_TYPE = 15;
constexpr int DEFAULT_DOMAIN_COUNT = 2;

} // namespace

class TestCDFAuthenticationJwt : public testing ::Test {
protected:
    void SetUp() override
    {
        EXPECT_TRUE(Logger::Instance()->SetExternalLogFunction(SetExternalLogCallBack));
    }

    void TearDown() override
    {
        // Perform any necessary cleanup for the test cases
    }
};

std::pair<KeyManagerRC, std::vector<std::byte>> StubEncrypt([[maybe_unused]] const CryptoSymAlg &symAlg,
                                                            [[maybe_unused]] uint32_t domainId,
                                                            [[maybe_unused]] std::string_view plaintext)
{
    std::vector<std::byte> vec(64);
    return {KeyManagerRC::OK, vec};
}

std::pair<KeyManagerRC, std::vector<std::byte>> StubEncrypt2([[maybe_unused]] const CryptoSymAlg &symAlg,
                                                            [[maybe_unused]] uint32_t domainId,
                                                            [[maybe_unused]] std::string_view plaintext)
{
    std::vector<std::byte> vec(64, std::byte(1));
    return {KeyManagerRC::OK, vec};
}

std::pair<KeyManagerRC, std::vector<std::byte>> StubDecrypt([[maybe_unused]] const CryptoSymAlg &alg,
                                                          [[maybe_unused]] uint32_t domainId,
                                                          [[maybe_unused]] std::string_view ciphertext)
{
    std::vector<std::byte> vec(64);
    return {KeyManagerRC::OK, vec};
}

std::pair<KeyManagerRC, std::vector<std::byte>> StubDecrypt2([[maybe_unused]] const CryptoSymAlg &alg,
                                                            [[maybe_unused]] uint32_t domainId,
                                                            [[maybe_unused]] std::string_view ciphertext)
{
    std::vector<std::byte> vec(64, std::byte(1));
    return {KeyManagerRC::OK, vec};
}

void SetStubOpenbaoFunc(Stub &stub)
{
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(GetJsonFieldMaxInt, StubGetJsonFieldMaxInt);
    stub.Set(GetJsonFieldAsStr, StubGetOpenbaoLastKeyAsStr);
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncrypt);
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt), StubDecrypt);
}

void UnSetOpenbaoFunc(Stub &stub)
{
    stub.Reset(RunCommandAndCheck);
    stub.Reset(GetJsonFieldAsStr);
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldMaxInt);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt));
}

std::string CreateJwtToken(JwtAuthServer *jwtServer, std::string key)
{
    jwtServer->SetEncryptionKey(key);

    std::string input = "userName@xidfswefhajsx";

    auto [result, tokenLen] = jwtServer->EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;

    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer->CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    return {token.data()};
}

TEST_F(TestCDFAuthenticationJwt, StartSuccess)
{
    JwtAuthServer jwtServer;

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);

    EXPECT_EQ(result, JwtAuthRC::OK);

    jwtServer.Stop();
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(TestCDFAuthenticationJwt, StartTwiceSuccess)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    JwtAuthServer jwtServer;
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    jwtServer.Stop();
    jwtServer.Stop();
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(TestCDFAuthenticationJwt, StartFailedParamInvalid)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    auto x = static_cast<CryptoHmacAlg>(INVALID_CDF_DIST_AUTH_ALG_TYPE);
    options.algType = x;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    jwtServer.Stop();
    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(TestCDFAuthenticationJwt, StartFailedExecPathInvalid)
{
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    auto x = static_cast<CryptoHmacAlg>(INVALID_CDF_DIST_AUTH_ALG_TYPE);
    options.algType = x;
    options.execPath = "abc";
    options.accessToken = "access_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    jwtServer.Stop();
}

TEST_F(TestCDFAuthenticationJwt, StartFailedDomainCountInvalid)
{
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    auto x = static_cast<CryptoHmacAlg>(INVALID_CDF_DIST_AUTH_ALG_TYPE);
    options.algType = x;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = 1;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    jwtServer.Stop();
}

TEST_F(TestCDFAuthenticationJwt, StartFailedFlagInvalid)
{
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    auto x = static_cast<CryptoHmacAlg>(INVALID_CDF_DIST_AUTH_ALG_TYPE);
    options.algType = x;
    const int invliadKeyMode = 2;
    options.keyTransferMode = static_cast<JwtAuthMode>(invliadKeyMode);

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    jwtServer.Stop();
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenFailedKeyExpired)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.serverKeyExpiredHours = 0;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "12345678123456781234567812345678";
    jwtServer.SetEncryptionKey(key);

    sleep(1); // wait for key expire

    std::string input = "userName@xidfswefhajsx";
    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);
    tokenLen++;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::KEY_PASS_INVALID);
    jwtServer.Stop();

    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenFailedParamWrong)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    jwtServer.SetEncryptionKey(key);

    std::string input = "userName@xidfswefhajsx";

    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = nullptr;
    tokenOptions.inputLen = 0;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    jwtServer.Stop();

    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenFailedTokenLenWrong)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    auto rc = jwtServer.SetEncryptionKey(key);
    EXPECT_EQ(rc, JwtAuthRC::OK);

    std::string input = "userName@xidfswefhajsx";

    uint32_t tokenLen = 1;

    const int tempTokenLen = 1024;
    std::vector<char> token(tempTokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::CREATE_TOKEN_FAIL);
    jwtServer.Stop();

    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, SetEncryptionKeyFail)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456";
    result = jwtServer.SetEncryptionKey(key);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    const size_t maxKeyLength = 1048576;
    std::string key2;
    key2.resize(maxKeyLength, 'a');
    result = jwtServer.SetEncryptionKey(key2);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    std::string key3;
    key3.resize(maxKeyLength - 1, 'a');
    result = jwtServer.SetEncryptionKey(key3);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();

    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenSuccess)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111111111";
    jwtServer.SetEncryptionKey(key);

    std::string input = "userName@xidfswefhajsx";

    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();

    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateSuccess)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);
    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();

    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateSuccessWithAlgShm384)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA384;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "1234567812345678123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);
    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();

    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateSuccessWithAlgShm512)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA512;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "12345678123456781234567812345678123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);
    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateParamWrong)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    jwtServer.SetEncryptionKey({});
    jwtServer.RefreshEncryptionKey({});
    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = nullptr;
    validateTokenOptions.tokenLen = 0;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateSuccessWithOldKey)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111111111";
    jwtServer.SetEncryptionKey(key);

    std::string input = "userName@xidfswefhajsx";

    uint32_t tokenLen = 0;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    key = "12345678123456781234567812345678";
    result = jwtServer.RefreshEncryptionKey(key);
    EXPECT_EQ(result, JwtAuthRC::OK);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = tokenOptions.token;
    validateTokenOptions.tokenLen = tokenOptions.tokenLen + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateFailedKeyError)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);

    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt));
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncrypt2);
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt), StubDecrypt2);
    std::string key2 = "12345678123456781234567812345678111111111";
    jwtServer.SetEncryptionKey(key2);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::TOKEN_VALIDATE_FAIL);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateFailedBothKeyError)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);

    std::string key1 = "123456781234567812345678123456781";
    std::string key2 = "123456781234567812345678123456781";
    jwtServer.SetEncryptionKey(key1);

    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
                               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
                               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt));
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncrypt2);
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt), StubDecrypt2);
    result = jwtServer.RefreshEncryptionKey(key2);
    EXPECT_EQ(result, JwtAuthRC::OK);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::TOKEN_VALIDATE_FAIL);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateFailedTokenExpire)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.tokenExpireMinutes = 0;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);

    sleep(1);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::TOKEN_EXPIRED);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenSuccessWithUserKey)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.keyTransferMode = JwtAuthMode::EXTERNAL_KEY;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string input = "userName@xidfswefhajsx";
    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.key = key.c_str();
    tokenOptions.keyLen = key.length() + 1;
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateSuccessWithUserKey)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.keyTransferMode = JwtAuthMode::EXTERNAL_KEY;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string input = {"userName@xidfswefhajsx"};
    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.key = key.c_str();
    tokenOptions.keyLen = key.length() + 1;
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.key = key.c_str();
    validateTokenOptions.keyLen = key.length() + 1;
    validateTokenOptions.token = tokenOptions.token;
    validateTokenOptions.tokenLen = tokenOptions.tokenLen + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, StartSuccessValidateTokenExpireMinutes)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = -1;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();

    int minTokenExpireMinutes = 1;
    options.tokenExpireMinutes = minTokenExpireMinutes;
    result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();

    int maxTokenExpireMinutes = 32767;
    options.tokenExpireMinutes = maxTokenExpireMinutes;
    result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, StartSuccessValidateServerKeyExpiredHours)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = -1;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    jwtServer.Stop();

    int minServerKeyExpiredHours = 1;
    options.serverKeyExpiredHours = minServerKeyExpiredHours;
    result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();

    int maxServerKeyExpiredHours = JWT_EXPIRE_TIME_MAX_MINUTE / JWT_MINUTES_PER_HOUR;
    options.serverKeyExpiredHours = maxServerKeyExpiredHours;
    result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateSuccessWithSetEncryptionKey)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781232131";
    uint32_t keyLen = 7;
    result = jwtServer.SetEncryptionKey(key);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string input = "abcdefg";
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.key = key.c_str();
    tokenOptions.keyLen = keyLen;

    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.key = tokenOptions.key;
    validateTokenOptions.keyLen = tokenOptions.keyLen;
    validateTokenOptions.token = tokenOptions.token;
    validateTokenOptions.tokenLen = tokenOptions.tokenLen + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateSuccessWithRefreshEncryptionKey)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;
    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key1 = "1234567812345678123456781234567893721";
    std::string key2 = "123456781234567812345678123456789372111";
    uint32_t len2 = 7;
    jwtServer.SetEncryptionKey(key1);

    result = jwtServer.RefreshEncryptionKey(key2);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string input = "abcdefg";
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.key = key2.c_str();
    tokenOptions.keyLen = len2;

    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.key = tokenOptions.key;
    validateTokenOptions.keyLen = tokenOptions.keyLen;
    validateTokenOptions.token = tokenOptions.token;
    validateTokenOptions.tokenLen = tokenOptions.tokenLen + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateFiledWithInconsistentKeys)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    auto jwtServer = std::make_unique<JwtAuthServer>();

    CDFDistAuthServerOptions options = {};
    options.keyTransferMode = JwtAuthMode::EXTERNAL_KEY;
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "12345678123456781234567812345678111111111";
    std::string key2 = "45645678123456781234567812345678111111111";
    std::string input = "userName@xidfswefhajsx";
    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer->EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen++;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.key = key.c_str();
    tokenOptions.keyLen = key.length() + 1;
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer->CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.key = key2.c_str();
    validateTokenOptions.keyLen = key2.length() + 1;
    validateTokenOptions.token = token.data();
    validateTokenOptions.tokenLen = tokenOptions.tokenLen + 1;
    result = jwtServer->ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::TOKEN_VALIDATE_FAIL);

    jwtServer->Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, StartJwtServerWithMasterKeyFileError)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    auto jwtServer = std::make_unique<JwtAuthServer>();

    // make sure openbao is uninted
    KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO)->UnInit();

    CDFDistAuthServerOptions options = {};
    options.keyTransferMode = JwtAuthMode::INTERNAL_KEY;
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;
    auto result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    options.execPath = "/aaa"; // invalid master file path
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    jwtServer->Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, RefreshEncryptionKeyTwice)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    auto jwtServer = std::make_unique<JwtAuthServer>();
    CDFDistAuthServerOptions options = {};
    options.keyTransferMode = JwtAuthMode::INTERNAL_KEY;
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "12345678123456781234567812345678111111111";
    std::string key2 = "456456781234567812345678123456781111111111";

    result = jwtServer->SetEncryptionKey(key);
    EXPECT_EQ(result, JwtAuthRC::OK);
    std::string input = "userName@xidfswefhajsx";
    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer->EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen++;
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer->CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);

    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
    stub.Reset(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt));
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncrypt2);
    stub.Set(static_cast<std::pair<KeyManagerRC, std::vector<std::byte>> (OpenbaoKeyManager::*)
        (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt), StubDecrypt2);
    result = jwtServer->RefreshEncryptionKey(key2);
    EXPECT_EQ(result, JwtAuthRC::OK);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = tokenOptions.token;
    validateTokenOptions.tokenLen = tokenOptions.tokenLen + 1;
    result = jwtServer->ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::TOKEN_VALIDATE_FAIL);

    jwtServer->Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateTokenValidateFailedTokenExpireAndServerKeyExpiredHours)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    auto jwtServer = std::make_unique<JwtAuthServer>();

    CDFDistAuthServerOptions options = {};
    options.tokenExpireMinutes = 0;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer->Stop();

    const int16_t testExpireTime1 = -2;
    const auto testExpireTime2 = static_cast<int16_t>(32768);
    options.tokenExpireMinutes = testExpireTime1;
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    jwtServer->Stop();

    options.tokenExpireMinutes = testExpireTime2;
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    jwtServer->Stop();

    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.serverKeyExpiredHours = 0;
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer->Stop();

    options.serverKeyExpiredHours = testExpireTime1;
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    jwtServer->Stop();

    options.serverKeyExpiredHours = testExpireTime2;
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    jwtServer->Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, StartJwtServerWithInvalidDomainId)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    auto jwtServer = std::make_unique<JwtAuthServer>();
    CDFDistAuthServerOptions options = {};
    options.keyTransferMode = JwtAuthMode::INTERNAL_KEY;
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    const int testDomainCount1 = 2;
    options.domainCount = testDomainCount1;
    options.domainId = -1;
    auto result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    const int testDomainCount2 = 1024;
    options.domainId = testDomainCount2;
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    options.domainId = testDomainCount2;
    options.domainCount = testDomainCount2;
    result = jwtServer->Start(options);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    jwtServer->Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, RefreshEncryptionKeyWithKeyError)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "./";
    options.accessToken = "test_token";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);

    const size_t minKeyLength = 32;
    const size_t maxKeyLength = 1048576;
    std::string key1;
    key1.resize(minKeyLength, 'a');
    result = jwtServer.RefreshEncryptionKey(key1);
    EXPECT_EQ(result, JwtAuthRC::OK);
    std::string key2;
    key2.resize(minKeyLength - 1, 'a');
    result = jwtServer.RefreshEncryptionKey(key2);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);

    std::string key3;
    key3.resize(maxKeyLength, 'a');
    result = jwtServer.RefreshEncryptionKey(key3);
    EXPECT_EQ(result, JwtAuthRC::PARAM_INVALID);
    std::string key4;
    key4.resize(maxKeyLength - 1, 'a');
    result = jwtServer.RefreshEncryptionKey(key4);
    EXPECT_EQ(result, JwtAuthRC::OK);

    jwtServer.Stop();
    UnSetOpenbaoFunc(stub);
}

TEST_F(TestCDFAuthenticationJwt, CreateValidateTokenWithoutServerStarted)
{
    Stub stub;
    SetStubOpenbaoFunc(stub);
    JwtAuthServer jwtServer;

    std::string key = "123456781234567812345678123456781232131";
    uint32_t keyLen = 7;
    auto result = jwtServer.SetEncryptionKey(key);
    EXPECT_EQ(result, JwtAuthRC::ERROR);

    std::string input = "abcdefg";
    CDFDistAuthCreateTokenOptions tokenOptions{};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.key = key.c_str();
    tokenOptions.keyLen = keyLen;

    uint32_t tokenLen;
    std::tie(result, tokenLen) = jwtServer.EstimateTokenLength(input.size());
    EXPECT_EQ(result, JwtAuthRC::OK);

    tokenLen += 1;
    std::vector<char> token(tokenLen);
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    result = jwtServer.CreateToken(tokenOptions);
    EXPECT_EQ(result, JwtAuthRC::ERROR);

    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.key = tokenOptions.key;
    validateTokenOptions.keyLen = tokenOptions.keyLen;
    validateTokenOptions.token = tokenOptions.token;
    validateTokenOptions.tokenLen = tokenOptions.tokenLen + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::ERROR);
    UnSetOpenbaoFunc(stub);
}

// 该用例使用真实安装openbao环境执行，验证无打桩执行
TEST_F(TestCDFAuthenticationJwt, DISABLED_CreateTokenValidateSuccessForRealOpenbao)
{
    JwtAuthServer jwtServer;

    CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;
    options.serverKeyExpiredHours = DEFAULT_SERVER_KEY_EXPIRED_HOURS;
    options.tokenExpireMinutes = DEFAULT_TOKEN_EXPIRE_MINUTES;
    options.execPath = "/usr/bin/bao";
    options.accessToken = "s.Q4IuMdHAsySZPNf1i5qeaqL2";
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;

    auto result = jwtServer.Start(options);
    EXPECT_EQ(result, JwtAuthRC::OK);

    std::string key = "123456781234567812345678123456781111";
    std::string token = CreateJwtToken(&jwtServer, key);
    CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    result = jwtServer.ValidateToken(validateTokenOptions);
    EXPECT_EQ(result, JwtAuthRC::OK);
    jwtServer.Stop();
}

} // namespace cdf::test
