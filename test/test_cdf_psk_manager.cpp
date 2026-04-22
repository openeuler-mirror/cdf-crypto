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

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "stub.h"
#include "test_utils.h"

#include "cdf/modules/cryption/km_cryptor.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/key_management/openbao/openbao_key_manager.h"
#include "cdf/modules/key_management/openbao/openbao_utils.h"
#include "cdf/modules/psk_management/psk_define.h"
#include "cdf/modules/psk_management/psk_manager.h"
#include "cdf/modules/rand/rand.h"

namespace cdf::test {

namespace {

const std::string KM_EXEPATH = "./";
const std::string KM_ACCESSTOKEN = "testToken";

constexpr int DEFAULT_DOMAIN_COUNT = 2;
const std::string TEMP_FILENAME = "test_bytes.bin"; // 临时文件

} // namespace

class TestCDFPskManager : public ::testing::Test {
protected:
    void SetUp() override
    {
        EXPECT_TRUE(Logger::Instance()->SetExternalLogFunction(SetExternalLogCallBack));
    }

    void TearDown() override {}
};

void SetDefaultInitOptions(PsKManagerInitOptions &options)
{
    options = {};
    options.algType = CryptoSymAlg::AES256_GCM;

    options.exePath = KM_EXEPATH;
    options.accessToken = KM_ACCESSTOKEN;
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;
    options.pskMaxCount = 1000;
}

void SetDefaultPskParam(PskParam &pskParam)
{
    pskParam.issuer = "Huawei";
    pskParam.subject = "Computing SecuritySolution";
    pskParam.pskLength = 256;
    pskParam.validDays = 30;
    pskParam.beginTime = std::time(nullptr);
}

bool SetSytemTimeToNow(const time_t now)
{
    tm timeinfo = *localtime(&now);
    tm temp = timeinfo; // 复制一份，因为 mktime 可能会修改 tm 结构体
    time_t newTime = mktime(&temp);

    // 设置系统时间
    struct timeval tv;
    tv.tv_sec = newTime; // 秒
    tv.tv_usec = 0;      // 微秒

    return settimeofday(&tv, nullptr) == 0;
}

bool SetSystemTimeToFuture(time_t now, int delayMouth)
{
    struct tm *timeinfo = localtime(&now);

    // 将时间调整为未来半年
    timeinfo->tm_mon += delayMouth;
    if (timeinfo->tm_mon > NUM_11) {
        timeinfo->tm_mon -= NUM_12;
        timeinfo->tm_year += 1;
    }

    // 转换为 time_t
    time_t future = mktime(timeinfo);

    // 设置系统时间
    struct timeval tv;
    tv.tv_sec = future;
    tv.tv_usec = 0;
    return settimeofday(&tv, nullptr) == 0;
}

PskManagerRC UpdatePskCb(const uint32_t pskId, const std::vector<std::byte> pskCiphertext)
{
    (void)pskId;
    (void)pskCiphertext;
    return PskManagerRC::OK;
}

PskManagerRC CreatePskCb(const uint32_t pskId, const std::vector<std::byte> pskCiphertext)
{
    (void)pskId;
    // 写入文件（二进制模式，保留原始字节）
    {
        std::ofstream ofs(TEMP_FILENAME, std::ios::binary); // 二进制模式关键

        // 写入字节数据（直接写 vector 的原始数据）
        ofs.write(reinterpret_cast<const char *>(pskCiphertext.data()), pskCiphertext.size());
    } // ofs 超出作用域自动关闭
    return PskManagerRC::OK;
}

PskManagerRC DeletePskCb(const uint32_t pskId)
{
    (void)pskId;
    return PskManagerRC::OK;
}

std::pair<KeyManagerRC, std::vector<std::byte>> StubEncryptPsk([[maybe_unused]] const CryptoSymAlg &symAlg,
                                                               [[maybe_unused]] uint32_t domainId,
                                                               [[maybe_unused]] std::string_view plaintext)
{
    std::vector<std::byte> vec;
    vec.push_back(std::byte(0));
    return {KeyManagerRC::OK, vec};
}

std::pair<KeyManagerRC, std::vector<std::byte>> StubDecryptPsk([[maybe_unused]] const CryptoSymAlg &symAlg,
                                                               [[maybe_unused]] uint32_t domainId,
                                                               [[maybe_unused]] std::string_view ciphertext)
{
    std::vector<int> int_vec = {
        65,  47,  106, 56,  75,  114, 54,  77,  118, 55,  80,  98,  114, 78,  104, 116, 97,  85,  115, 117, 52,  76,
        49,  82,  57,  102, 84,  109, 43,  66,  55,  43,  69,  80,  84,  102, 121, 81,  99,  50,  89,  69,  99,  98,
        112, 102, 71,  88,  75,  83,  48,  69,  89,  88,  78,  51,  109, 100, 88,  70,  122, 88,  114, 99,  112, 78,
        89,  81,  104, 98,  80,  70,  66,  89,  116, 49,  103, 115, 100, 87,  84,  84,  79,  113, 47,  99,  99,  98,
        82,  90,  47,  101, 90,  79,  77,  55,  89,  57,  118, 67,  87,  82,  71,  108, 76,  79,  85,  67,  50,  67,
        69,  84,  117, 54,  50,  83,  115, 80,  100, 118, 108, 121, 43,  55,  81,  67,  52,  107, 85,  78,  74,  56,
        77,  114, 119, 114, 49,  81,  110, 57,  85,  102, 73,  104, 88,  104, 109, 68,  47,  88,  52,  114, 116, 67,
        76,  118, 65,  114, 67,  104, 56,  118, 97,  107, 81,  101, 47,  111, 87,  57,  107, 74,  99,  97,  78,  110,
        89,  86,  76,  70,  55,  71,  83,  85,  111, 110, 110, 90,  105, 97,  76,  50,  87,  67,  78,  120, 122, 51,
        43,  55,  110, 79,  110, 53,  121, 73,  84,  56,  98,  117, 55,  103, 70,  54,  52,  117, 120, 83,  74,  98,
        69,  52,  53,  43,  48,  119, 68,  97,  79,  112, 80,  69,  51,  51,  74,  120, 105, 68,  85,  69,  81,  52,
        82,  56,  72,  70,  75,  68,  67,  65,  89,  71,  51,  103, 103, 103, 97,  115, 65,  84,  107, 103, 78,  52,
        104, 72,  69,  79,  65,  121, 69,  75,  54,  97,  105, 78,  102, 57,  53,  115, 48,  110, 104, 51,  101, 111,
        113, 74,  100, 49,  118, 87,  108, 81,  77,  105, 50,  65,  51,  97,  73,  65,  84,  119, 43,  112, 115, 54,
        107, 87,  115, 71,  57,  71,  109, 108, 107, 54,  73,  115, 49,  56,  72,  54,  79,  112, 47,  98,  73,  72,
        81,  74,  112, 71,  77,  85,  54,  52,  68,  108, 77,  81,  61,  61,  46,  101, 121, 74,  119, 99,  50,  116,
        74,  90,  67,  73,  54,  77,  83,  119, 105, 97,  88,  78,  122, 100, 87,  86,  121, 73,  106, 111, 105, 83,
        72,  86,  104, 100, 50,  86,  112, 73,  105, 119, 105, 99,  51,  86,  105, 97,  109, 86,  106, 100, 67,  73,
        54,  73,  107, 78,  118, 98,  88,  66,  49,  100, 71,  108, 117, 90,  121, 66,  84,  90,  87,  78,  49,  99,
        109, 108, 48,  101, 86,  78,  118, 98,  72,  86,  48,  97,  87,  57,  117, 73,  105, 119, 105, 99,  72,  78,
        114, 84,  71,  86,  117, 90,  51,  82,  111, 73,  106, 111, 121, 78,  84,  89,  115, 73,  110, 90,  104, 98,
        71,  108, 107, 82,  71,  70,  53,  99,  121, 73,  54,  77,  122, 65,  115, 73,  109, 74,  108, 90,  50,  108,
        117, 86,  71,  108, 116, 90,  83,  73,  54,  73,  106, 73,  119, 77,  106, 85,  116, 77,  84,  69,  116, 77,
        106, 103, 103, 77,  84,  85,  54,  77,  122, 65,  54,  77,  122, 69,  105, 76,  67,  74,  108, 98,  109, 82,
        85,  97,  87,  49,  108, 73,  106, 111, 105, 77,  106, 65,  121, 78,  83,  48,  120, 77,  105, 48,  121, 79,
        67,  65,  120, 78,  84,  111, 122, 77,  68,  111, 122, 77,  83,  74,  57};
    std::vector<std::byte> vec;

    for (int value : int_vec) {
        vec.push_back(static_cast<std::byte>(value));
    }
    return {KeyManagerRC::OK, vec};
}

TEST_F(TestCDFPskManager, InitExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);

    PsKManagerInitOptions options = {};
    options = {};
    options.exePath = KM_EXEPATH;
    options.accessToken = KM_ACCESSTOKEN;
    options.domainCount = DEFAULT_DOMAIN_COUNT;
    options.domainId = 0;
    options.pskMaxCount = 1000;

    options.algType = CryptoSymAlg::AES256_GCM;
    options.domainCount = 1023;
    options.domainId = 0;
    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);
    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    options.algType = CryptoSymAlg::CHACHA20_POLY1305;
    options.domainCount = 1023;
    options.domainId = 1022;
    ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);
    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    options.pskMaxCount = 1;
    ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);
    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    options.pskMaxCount = 4294967295;
    ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);
    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    options.pskMaxCount = 2147483647;
    ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);
    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
}

TEST_F(TestCDFPskManager, NoInitExpectError)
{
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt),
             StubEncryptPsk);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    Psk updatePsk;
    ret = pskMgr.UpdatePsk(outputPsk.GetPskId(), outputPsk.GetPskContent(), updatePsk);
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    ret = pskMgr.DeletePsk(outputPsk.GetPskId());
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    ret = pskMgr.CheckPskValid(outputPsk.GetPskId());
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    ret = pskMgr.CheckPskValidAndAutoUpdate(outputPsk.GetPskId());
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    std::vector<std::string> pskList;
    ret = pskMgr.LoadAllPsk(pskList);
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    std::vector<uint8_t> pskContent;
    ret = pskMgr.GetPsk(outputPsk.GetPskId(), pskContent);
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    PskMetaData pskMetaData;
    ret = pskMgr.GetPskMetaData(outputPsk.GetPskId(), pskMetaData);
    EXPECT_EQ(ret, PskManagerRC::UNINITED);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, GeneratePskExpectOK)
{
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    pskParam.issuer = "Huawei";
    pskParam.subject = "Computing SecuritySolution";
    pskParam.pskLength = 256;
    pskParam.validDays = 30;
    pskParam.beginTime = std::time(nullptr);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    pskParam.issuer = "H";
    pskParam.subject = "C";
    pskParam.validDays = 1;
    pskParam.pskLength = 384;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    // 64长度字符
    pskParam.issuer = "Huawei11Huawei11Huawei11Huawei11Huawei11Huawei11Huawei11Huawei11";
    pskParam.subject = "ComputinComputinComputinComputinComputinComputinComputinComputin";
    pskParam.validDays = 1;
    pskParam.pskLength = 512;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskCallbackMgr &manager = PskCallbackMgr::GetInstance();
    manager.RegisterCreatePskCallBack(CreatePskCb);
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    std::remove(TEMP_FILENAME.c_str());
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, ImportPskExpectOK)
{
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    std::vector<uint8_t> pskContent(pskParam.pskLength);
    auto randRet = RandInit();
    EXPECT_EQ(randRet, CcsecCryptErrorCode::CCSEC_CRYPT_OK);
    // 生成随机数据
    randRet = GetRand(pskContent.data(), pskParam.pskLength);
    EXPECT_EQ(randRet, CcsecCryptErrorCode::CCSEC_CRYPT_OK);

    Psk outputPsk;
    ret = pskMgr.ImportPsk(pskParam, pskContent, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, UpdatePskExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    sleep(1); // 休息1秒，判断更新后的开始时间是否更改
    // 没有注册回调函数时，输入正确的pskId及pskContent，成功更新Psk
    Psk updatePsk;
    auto updateRet = pskMgr.UpdatePsk(outputPsk.GetPskId(), outputPsk.GetPskContent(), updatePsk);
    EXPECT_EQ(updateRet, PskManagerRC::OK); // 基本信息不变，密钥、开始时间、结束时间变更
    EXPECT_EQ(outputPsk.GetPskId(), updatePsk.GetPskId());
    EXPECT_EQ(outputPsk.GetIssuer(), updatePsk.GetIssuer());
    EXPECT_EQ(outputPsk.GetSubject(), updatePsk.GetSubject());
    EXPECT_EQ(outputPsk.GetValidDays(), updatePsk.GetValidDays());
    EXPECT_NE(outputPsk.GetPskContent(), updatePsk.GetPskContent());
    EXPECT_NE(outputPsk.GetBeginTime(), updatePsk.GetBeginTime());
    EXPECT_NE(outputPsk.GetEndTime(), updatePsk.GetEndTime());

    sleep(1);
    // 注册回调函数时，输入正确的pskId及pskContent，成功更新Psk
    Psk updatePsk1;
    PskCallbackMgr &manager = PskCallbackMgr::GetInstance();
    manager.RegisterUpdatePskCallBack(UpdatePskCb);
    updateRet = pskMgr.UpdatePsk(updatePsk.GetPskId(), updatePsk.GetPskContent(), updatePsk1);
    EXPECT_EQ(updateRet, PskManagerRC::OK);
    EXPECT_EQ(updatePsk.GetPskId(), updatePsk1.GetPskId());
    EXPECT_EQ(updatePsk.GetIssuer(), updatePsk1.GetIssuer());
    EXPECT_EQ(updatePsk.GetSubject(), updatePsk1.GetSubject());
    EXPECT_EQ(updatePsk.GetValidDays(), updatePsk1.GetValidDays());
    EXPECT_NE(updatePsk.GetPskContent(), updatePsk1.GetPskContent());
    EXPECT_NE(updatePsk.GetBeginTime(), updatePsk1.GetBeginTime());
    EXPECT_NE(updatePsk.GetEndTime(), updatePsk1.GetEndTime());

    sleep(1);
    // 注册回调函数时，仅输入正确的pskId，成功更新Psk
    Psk updatePsk2;
    updateRet = pskMgr.UpdatePsk(updatePsk1.GetPskId(), {}, updatePsk2);
    EXPECT_EQ(updateRet, PskManagerRC::OK);
    EXPECT_EQ(updatePsk1.GetPskId(), updatePsk2.GetPskId());
    EXPECT_EQ(updatePsk1.GetIssuer(), updatePsk2.GetIssuer());
    EXPECT_EQ(updatePsk1.GetSubject(), updatePsk2.GetSubject());
    EXPECT_EQ(updatePsk1.GetValidDays(), updatePsk2.GetValidDays());
    EXPECT_NE(updatePsk1.GetPskContent(), updatePsk2.GetPskContent());
    EXPECT_NE(updatePsk1.GetBeginTime(), updatePsk2.GetBeginTime());
    EXPECT_NE(updatePsk1.GetEndTime(), updatePsk2.GetEndTime());

    sleep(1);
    // 注册回调函数时，仅输入正确的pskContent，成功更新Psk
    Psk updatePsk3;
    updateRet = pskMgr.UpdatePsk(-1, updatePsk2.GetPskContent(), updatePsk3);
    EXPECT_EQ(updateRet, PskManagerRC::OK);
    updateRet = pskMgr.UpdatePsk(0, updatePsk3.GetPskContent(), updatePsk3);
    EXPECT_EQ(updateRet, PskManagerRC::OK);
    updateRet = pskMgr.UpdatePsk(4294967295, updatePsk3.GetPskContent(), updatePsk3);
    EXPECT_EQ(updateRet, PskManagerRC::OK);
    EXPECT_EQ(updatePsk2.GetPskId(), updatePsk3.GetPskId());
    EXPECT_EQ(updatePsk2.GetIssuer(), updatePsk3.GetIssuer());
    EXPECT_EQ(updatePsk2.GetSubject(), updatePsk3.GetSubject());
    EXPECT_EQ(updatePsk2.GetValidDays(), updatePsk3.GetValidDays());
    EXPECT_NE(updatePsk2.GetPskContent(), updatePsk3.GetPskContent());
    EXPECT_NE(updatePsk2.GetBeginTime(), updatePsk3.GetBeginTime());
    EXPECT_NE(updatePsk2.GetEndTime(), updatePsk3.GetEndTime());

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, UpdatePskExpectError)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    Psk outputPsk1;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk1);
    EXPECT_EQ(ret, PskManagerRC::OK);

    std::vector<uint8_t> wrongPskContent = outputPsk.GetPskContent();
    wrongPskContent.emplace_back(1);

    Psk updatePsk;
    // 输入错误的pskId和pskContent，无法更新
    auto updateRet = pskMgr.UpdatePsk(10000, wrongPskContent, updatePsk);
    EXPECT_NE(updateRet, PskManagerRC::OK);

    // 输入正确的pskId和pskContent，但两者对应的不是一个psk，无法更新
    updateRet = pskMgr.UpdatePsk(outputPsk.GetPskId(), outputPsk1.GetPskContent(), updatePsk);
    EXPECT_NE(updateRet, PskManagerRC::OK);

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, DeletePskExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    std::vector<uint8_t> pskContent;
    ret = pskMgr.GetPsk(outputPsk.GetPskId(), pskContent);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskCallbackMgr &manager = PskCallbackMgr::GetInstance();
    manager.RegisterDeletePskCallBack(DeletePskCb);
    ret = pskMgr.DeletePsk(outputPsk.GetPskId());
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.GetPsk(outputPsk.GetPskId(), pskContent);
    EXPECT_NE(ret, PskManagerRC::OK);

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, CheckPskValidExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    // 检查未过期状态
    ret = pskMgr.CheckPskValid(outputPsk.GetPskId());
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, CheckPskValidAndAutoUpdateExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    // 检查未过期状态
    ret = pskMgr.CheckPskValidAndAutoUpdate(outputPsk.GetPskId());
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, LoadPskExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt), StubDecryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    PskCallbackMgr &manager = PskCallbackMgr::GetInstance();
    manager.RegisterCreatePskCallBack(CreatePskCb);
    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    // 去初始化重新初始化，清除psk的map中的数据
    ret = pskMgr.UnInit();
    EXPECT_EQ(ret, PskManagerRC::OK);
    ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    // 当前map中不存在psk
    std::vector<uint8_t> pskContent;
    ret = pskMgr.GetPsk(2, pskContent);
    EXPECT_EQ(ret, PskManagerRC::PSK_NOT_EXIST);

    // 读取回调函数存储的文件到 string 类型
    std::string readStr;
    {
        std::ifstream ifs(TEMP_FILENAME, std::ios::binary | std::ios::ate);
        ASSERT_TRUE(ifs.is_open());

        // 获取文件大小，预分配 string 内存
        std::streamsize size = ifs.tellg();
        readStr.resize(static_cast<size_t>(size));

        // 定位到文件头，读取所有字节
        ifs.seekg(0);
        ifs.read(readStr.data(), size);
        ASSERT_TRUE(ifs.good());
    } // ifs 超出作用域自动关闭
    std::vector<std::string> read_strs = {readStr};
    std::remove(TEMP_FILENAME.c_str());
    // Load存储文件中的字符串
    std::vector<std::string> pskList;
    pskList.push_back(readStr);
    pskList.push_back(readStr);
    ret = pskMgr.LoadAllPsk(pskList);
    EXPECT_EQ(ret, PskManagerRC::OK);

    ret = pskMgr.GetPsk(1, pskContent);
    EXPECT_EQ(ret, PskManagerRC::OK);
    ret = pskMgr.GetPsk(2, pskContent);
    EXPECT_EQ(ret, PskManagerRC::OK);

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Decrypt));
}

TEST_F(TestCDFPskManager, GetPskExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    std::vector<uint8_t> pskContent;
    ret = pskMgr.GetPsk(outputPsk.GetPskId(), pskContent);
    EXPECT_EQ(ret, PskManagerRC::OK);

    EXPECT_EQ(pskContent, outputPsk.GetPskContent());

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

TEST_F(TestCDFPskManager, GetPskMetaDataExpectOK)
{
    Stub stub;
    stub.Set(RunCommandAndGetResult, StubRunCommandAndGetResult);
    stub.Set(GetJsonFieldIntPairVec, StubGetJsonFieldIntPairVec);
    stub.Set(static_cast<std::pair<KeyManagerRC,
             std::vector<std::byte>> (OpenbaoKeyManager::*)
             (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt), StubEncryptPsk);
    // 先生成新的PSK
    PsKManagerInitOptions options = {};
    SetDefaultInitOptions(options);

    auto &pskMgr = PskManager::GetInstance();
    auto ret = pskMgr.Init(options);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskParam pskParam = {};
    SetDefaultPskParam(pskParam);

    Psk outputPsk;
    ret = pskMgr.GeneratePsk(pskParam, outputPsk);
    EXPECT_EQ(ret, PskManagerRC::OK);

    PskMetaData pskMetaData;
    ret = pskMgr.GetPskMetaData(outputPsk.GetPskId(), pskMetaData);
    EXPECT_EQ(ret, PskManagerRC::OK);

    EXPECT_EQ(pskMetaData.pskId, outputPsk.GetPskId());
    EXPECT_EQ(pskMetaData.issuer, "Huawei");
    EXPECT_EQ(pskMetaData.subject, "Computing SecuritySolution");
    EXPECT_EQ(pskMetaData.pskLength, static_cast<uint32_t>(256));
    EXPECT_EQ(pskMetaData.validDays, static_cast<uint32_t>(30));
    EXPECT_EQ(pskMetaData.beginTime, outputPsk.GetBeginTime());
    EXPECT_EQ(pskMetaData.endTime, outputPsk.GetEndTime());

    stub.Reset(RunCommandAndGetResult);
    stub.Reset(GetJsonFieldIntPairVec);
    stub.Reset(static_cast<std::pair<KeyManagerRC,
               std::vector<std::byte>> (OpenbaoKeyManager::*)
               (const CryptoSymAlg &, uint32_t, std::string_view)>(&OpenbaoKeyManager::Encrypt));
}

} // namespace cdf::test