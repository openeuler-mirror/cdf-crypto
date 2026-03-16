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

#include "cdf/modules/psk_management/psk_manager.h"

#include <unistd.h>
#include <iomanip>
#include <sstream>

#include "securec/securec.h"
#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/modules/cryption/km_cryptor.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/psk_management/psk_define.h"
#include "cdf/modules/rand/rand.h"
#include "cdf/utils/base64.h"
#include "cdf/utils/file_utils.h"

namespace cdf {
using namespace rapidjson;

std::atomic<int> PskManager::initCount_{0};

PskManager &PskManager::GetInstance()
{
    static PskManager pskManager;
    return pskManager;
}

PskManagerRC PskManager::ValidateInitOptions(const PsKManagerInitOptions &opt)
{
    // 校验加密算法类型
    if (opt.algType != CryptoSymAlg::AES256_GCM && opt.algType != CryptoSymAlg::CHACHA20_POLY1305) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|END|returnF|invalid algType");
        return PskManagerRC::INVALID_PARAM;
    }
    // 校验km类型
    if (opt.keyManagerType != KeyManagerTy::OPENBAO && opt.keyManagerType != KeyManagerTy::VAULT) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|END|returnF|invalid keyManagerType");
        return PskManagerRC::INVALID_PARAM;
    }
    if (opt.exePath.data() == nullptr) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|returnF|exePath is nullptr");
        return PskManagerRC::INVALID_PARAM;
    }
    std::string exePathStr(opt.exePath);
    // 校验path
    if (!FileUtils::CanonicalPath(exePathStr) || !FileUtils::CheckUserAccess(exePathStr, (R_OK | X_OK))) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|returnF|Invalid bianry path, or missing read & execute permission");
        return PskManagerRC::INVALID_PARAM;
    }
    if (opt.accessToken.data() == nullptr) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|returnF|accessToken is nullptr");
        return PskManagerRC::INVALID_PARAM;
    }
    // 校验token
    if (opt.accessToken.empty()) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|END|returnF||accessToken is empty.");
        return PskManagerRC::INVALID_PARAM;
    }
    // 校验domainId，domainCount 在Init中校验
    if (opt.domainId >= opt.domainCount) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|END|returnF|invalid domain id: "
                        << opt.domainId << ", bigger than domainCount");
        return PskManagerRC::INVALID_PARAM;
    }
    // 校验允许创建Psk最大数量
    if (opt.pskMaxCount < PSK_MAX_COUNT_LIMIT_MIN || opt.pskMaxCount > PSK_MAX_COUNT_LIMIT_MAX) {
        CCSEC_LOG_ERROR("|ValidateInitOptions|END|returnF||pskMaxCount is invalid: "<< opt.pskMaxCount
                        << ", must in range [" << PSK_MAX_COUNT_LIMIT_MIN << ", " << PSK_MAX_COUNT_LIMIT_MAX << "].");
        return PskManagerRC::INVALID_PARAM;
    }

    options_ = opt;
    return PskManagerRC::OK;
}

PskManagerRC PskManager::Init(const PsKManagerInitOptions &opt)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (CheckInited()) {
        initCount_++;
        CCSEC_LOG_INFO("|PskManager::Init|END|returnS|psk manager has been initialized, ignored.");
        return PskManagerRC::OK;
    }
    auto result = ValidateInitOptions(opt);
    if (result != PskManagerRC::OK) {
        return result;
    }
    // 初始化km
    auto *km = KeyManagerFactory::Borrow(options_.keyManagerType);
    if (km == nullptr) {
        CCSEC_LOG_ERROR("|PskManager::Init|END|returnF||borrow KM KeyManager failed.");
        return PskManagerRC::ERROR;
    }
    auto rc = km->Init(options_.exePath, options_.accessToken, options_.domainCount);
    if (rc != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("|PskManager::Init|END|returnF||Key manager init failed.");
        return PskManagerRC::INIT_FAILED;
    }
    initCount_++;
    CCSEC_LOG_INFO("|PskManager::Init|END|returnS|psk manager init successfully");
    return PskManagerRC::OK;
}

PskManagerRC PskManager::UnInit()
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    initCount_--;
    if (initCount_.load() < 0) {
        initCount_ = 0;
        CCSEC_LOG_INFO("|PskManager::UnInit|END|returnS||initCount_ is less than 0, reset it to 0.");
        return PskManagerRC::OK;
    }
    if (initCount_.load() > 0) {
        CCSEC_LOG_INFO("|PskManager::UnInit|END|returnS||multiple init require multiple uninit.");
        return PskManagerRC::OK;
    }
    // 去初始化km
    auto *km = KeyManagerFactory::Borrow(options_.keyManagerType);
    if (km == nullptr) {
        CCSEC_LOG_ERROR("|PskManager::UnInit|END|returnF||borrow KM KeyManager failed.");
        return PskManagerRC::ERROR;
    }
    auto rc = km->UnInit();
    if (rc != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("|PskManager::UnInit|END|returnF||key manager UnInit failed.");
        return PskManagerRC::INIT_FAILED;
    }
    // 清空 PSK 数据
    pskContentMap_.clear();
    pskIdMap_.clear();
    // 重置状态
    curPskMaxId_ = 1;
    options_ = PsKManagerInitOptions{};
    CCSEC_LOG_INFO("|PskManager::UnInit|END|returnS|psk manager init successfully");
    return PskManagerRC::OK;
}

PskManagerRC PskManager::ValidatePskParams(const PskParam &pskParam)
{
    if (curPskMaxId_ > options_.pskMaxCount) {
        CCSEC_LOG_ERROR("|ValidatePskParams|END|returnF|curPskMaxId:" << curPskMaxId_.load() << " reaches limit");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskParam.issuer.length() < PSK_ISSUER_LENGTH_MIN || pskParam.issuer.length() > PSK_ISSUER_LENGTH_MAX) {
        CCSEC_LOG_ERROR("|ValidatePskParams|END|returnF||length of issuer is invalid: "<< pskParam.issuer.length()
                        << ", length must in range [" << PSK_ISSUER_LENGTH_MIN << ", " << PSK_ISSUER_LENGTH_MAX <<
                        "].");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskParam.subject.length() < PSK_SUBJECT_LENGTH_MIN || pskParam.subject.length() > PSK_SUBJECT_LENGTH_MAX) {
        CCSEC_LOG_ERROR("|ValidatePskParams|END|returnF||length of subject is invalid: "<< pskParam.subject.length()
                        << ", length must in range [" << PSK_SUBJECT_LENGTH_MIN << ", " << PSK_SUBJECT_LENGTH_MAX <<
                        "].");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskParam.pskLength != PSK_LENGTH_256 && pskParam.pskLength != PSK_LENGTH_384 &&
        pskParam.pskLength != PSK_LENGTH_512) {
        CCSEC_LOG_ERROR("|ValidatePskParams|END|returnF||pskLength is invalid: "<< pskParam.pskLength << ", "
                        "pskLength value must in [" << PSK_LENGTH_256 << ", " << PSK_LENGTH_384 << ", " <<
                        PSK_LENGTH_512 << "].");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskParam.validDays < PSK_VALID_DAYS_MIN || pskParam.validDays > PSK_VALID_DAYS_MAX) {
        CCSEC_LOG_ERROR("|ValidatePskParams|END|returnF||validDays is invalid: "<< pskParam.validDays << ", length "
                        "must in range [" << PSK_VALID_DAYS_MIN << ", " << PSK_VALID_DAYS_MAX << "].");
        return PskManagerRC::INVALID_PARAM;
    }
    return PskManagerRC::OK;
}

std::string FormatTime(std::time_t timeValue)
{
    std::tm *timeInfo = std::localtime(&timeValue);
    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeInfo);
    return std::string(buffer);
}

PskManagerRC ParseTime(const std::string& timeStr, std::time_t &parseTime)
{
    std::tm tm = {};
    // 使用 strptime 解析时间字符串
    const char* result = strptime(timeStr.c_str(), "%Y-%m-%d %H:%M:%S", &tm);

    if (result == nullptr || *result != '\0') {
        CCSEC_LOG_ERROR("|ParseTime|END|returnF||failed to parse time string: %s" << timeStr);
        return PskManagerRC::ERROR;
    }

    // 转换为 time_t
    parseTime = std::mktime(&tm);
    if (parseTime == -1) {
        CCSEC_LOG_ERROR("|ParseTime|END|returnF||failed to convert tm to time_t");
        return PskManagerRC::ERROR;
    }

    return PskManagerRC::OK;
}

PskManagerRC PskManager::ConstructPskMetaJsonString(const Psk &psk, std::string &pskMetaJson)
{
    // 构造psk meta 信息json字符串
    Document doc;
    doc.SetObject();
    auto &allocator = doc.GetAllocator();

    doc.AddMember("pskId", psk.GetPskId(), allocator);
    doc.AddMember("issuer", Value(psk.GetIssuer().c_str(), allocator), allocator);
    doc.AddMember("subject", Value(psk.GetSubject().c_str(), allocator), allocator);
    doc.AddMember("pskLength", psk.GetPskLength(), allocator);
    doc.AddMember("validDays", psk.GetValidDays(), allocator);

    std::string formattedBeginTime = FormatTime(psk.GetBeginTime());
    std::string formattedEndTime = FormatTime(psk.GetEndTime());
    doc.AddMember("beginTime", Value(formattedBeginTime.c_str(), allocator), allocator);
    doc.AddMember("endTime", Value(formattedEndTime.c_str(), allocator), allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);
    pskMetaJson = buffer.GetString();
    return PskManagerRC::OK;
}

void PskManager::BuildPskObj(const PskParam &pskParam, const std::vector<uint8_t> &pskContent, Psk &psk)
{
    psk.SetPskId(curPskMaxId_.load());
    psk.SetIssuer(pskParam.issuer);
    psk.SetSubject(pskParam.subject);
    psk.SetPskLength(pskParam.pskLength);
    psk.SetPskContent(pskContent);
    psk.SetValidDays(pskParam.validDays);
    psk.SetBeginTime(pskParam.beginTime);
    auto endTime = pskParam.beginTime + (pskParam.validDays * DAY_TO_SECOND_TIME);
    psk.SetEndTime(endTime);
}

PskManagerRC PskManager::GeneratePskContent(uint32_t pskLength, std::vector<uint8_t> &pskContent)
{
    if (pskLength == 0) {
        CCSEC_LOG_ERROR("|GeneratePskContent|END|returnF||pskLength is 0");
        return PskManagerRC::INVALID_PARAM;
    }
    pskContent.resize(pskLength);

    std::ifstream randomDev("/dev/random", std::ios::in | std::ios::binary);
    if (!randomDev.is_open()) {
        CCSEC_LOG_ERROR("|GeneratePskContent|END|returnF||failed to read /dev/random");
        return PskManagerRC::ERROR;
    }

    // 从 /dev/random 读取指定长度的随机字节
    randomDev.read(reinterpret_cast<char*>(pskContent.data()), pskLength);

    // 检查是否成功读取了足够的数据
    if (randomDev.gcount() != static_cast<std::streamsize>(pskLength)) {
        CCSEC_LOG_ERROR("|GeneratePskContent|END|returnF||failed to read random data");
        pskContent.clear(); // 读取失败，清空向量
        return PskManagerRC::ERROR;
    }

    return PskManagerRC::OK;
}

PskManagerRC PskManager::EncryptPskToken(const std::vector<std::byte> &pskToken,
                                         std::vector<std::byte> &encryptedToken) const
{
    // 调用km进行加密
    auto [rc, cipher] = KmCryptor(options_.keyManagerType).Encrypt(options_.algType,
                                                                   MakeStringView(pskToken), options_.domainId);

    if (rc != CryptionRC::OK) {
        CCSEC_LOG_ERROR("|EncryptPskToken|END|returnF||key manager encrypt failed");
        return PskManagerRC::ENCRYPTO_FAIL;
    }

    encryptedToken = cipher;
    return PskManagerRC::OK;
}

PskManagerRC PskManager::DecryptPskCiphertext(const std::string &pskCiphertext,
                                              std::vector<std::byte> &pskToken) const
{
    // 调用km模块进行加密
    auto [rc, plaintext] = KmCryptor(options_.keyManagerType).Decrypt(
        options_.algType, std::string_view(pskCiphertext), options_.domainId);

    if (rc != CryptionRC::OK) {
        CCSEC_LOG_ERROR("|DecryptPskCiphertext|END|returnF||key manager decrypt failed");
        return PskManagerRC::DECRYPTO_FAIL;
    }

    pskToken = plaintext;
    memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());
    return PskManagerRC::OK;
}

std::vector<std::byte> PskManager::ConcatenatePskToken(const std::vector<uint8_t> &pskContent,
                                                       const std::string &pskMetaJson)
{
    // Base64编码
    auto pskContentB64 = Base64Encode(reinterpret_cast<const char *>(pskContent.data()), pskContent.size());
    auto pskMetaB64 = Base64Encode(pskMetaJson.c_str(), pskMetaJson.size());

    std::vector<std::byte> token;
    // 预分配内存：内容 + 点号 + 元数据
    token.reserve(pskContentB64.size() + 1 + pskMetaB64.size());

    token.insert(token.end(), pskContentB64.begin(), pskContentB64.end());
    token.push_back(ToByte('.'));
    token.insert(token.end(), pskMetaB64.begin(), pskMetaB64.end());

    return token;
}

PskManagerRC PskManager::BuildAndEncryptPskToken(const Psk &psk, std::vector<std::byte> &encryptedPskToken)
{
    // 构造PSK元数据JSON字符串
    std::string pskMetaJson;
    auto result = ConstructPskMetaJsonString(psk, pskMetaJson);
    if (result != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|BuildAndEncryptPskToken|END|returnF||failed to construct psk meta json string");
        return result;
    }

    // 获取PSK内容
    auto pskContent = psk.GetPskContent();

    // 拼接PSK Token
    auto pskToken = ConcatenatePskToken(pskContent, pskMetaJson);

    // 加密PSK Token
    auto ret = EncryptPskToken(pskToken, encryptedPskToken);

    // 清除敏感信息
    memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
    memset_s(pskToken.data(), pskToken.size(), 0, pskToken.size());
    return ret;
}

PskManagerRC PskManager::TriggerCreatePskCallback(uint32_t pskId, const std::vector<std::byte> &encryptedPskToken)
{
    if (PskCallbackMgr::GetInstance().IsCallbackRegistered(PskCallBackType::CREATE_PSK) != PskManagerRC::OK) {
        CCSEC_LOG_INFO("|TriggerCreatePskCallback||||create psk callback is unregistered, skip trigger");
        return PskManagerRC::OK;
    }
    auto cbRet = PskCallbackMgr::GetInstance().Trigger(PskCallBackType::CREATE_PSK, pskId, encryptedPskToken);
    if (cbRet != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|TriggerCreatePskCallback|END|returnF||failed to trigger create psk callback, cbRet: "
                        << static_cast<int>(cbRet));
        return PskManagerRC::CALL_BACK_EXECUTE_FAILED;
    }
    return PskManagerRC::OK;
}

PskManagerRC PskManager::TriggerUpdatePskCallback(uint32_t pskId, const std::vector<std::byte> &encryptedPskToken)
{
    if (PskCallbackMgr::GetInstance().IsCallbackRegistered(PskCallBackType::UPDATE_PSK) != PskManagerRC::OK) {
        CCSEC_LOG_INFO("|TriggerUpdatePskCallback||||update psk callback is unregistered, skip trigger");
        return PskManagerRC::OK;
    }
    auto cbRet = PskCallbackMgr::GetInstance().Trigger(PskCallBackType::UPDATE_PSK, pskId, encryptedPskToken);
    if (cbRet != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|TriggerUpdatePskCallback|END|returnF||failed to trigger create psk callback, cbRet: "
                        << static_cast<int>(cbRet));
        return PskManagerRC::CALL_BACK_EXECUTE_FAILED;
    }
    return PskManagerRC::OK;
}


PskManagerRC PskManager::TriggerDeletePskCallback(uint32_t pskId)
{
    if (PskCallbackMgr::GetInstance().IsCallbackRegistered(PskCallBackType::DELETE_PSK) != PskManagerRC::OK) {
        CCSEC_LOG_INFO("|TriggerDeletePskCallback||||delete psk callback is unregistered, skip trigger");
        return PskManagerRC::OK;
    }
    auto cbRet = PskCallbackMgr::GetInstance().Trigger(PskCallBackType::DELETE_PSK, pskId);
    if (cbRet != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|TriggerDeletePskCallback|END|returnF||failed to trigger delete psk callback, cbRet: "
                        << static_cast<int>(cbRet));
        return PskManagerRC::CALL_BACK_EXECUTE_FAILED;
    }
    return PskManagerRC::OK;
}

PskManagerRC PskManager::GeneratePsk(const PskParam &pskParam, Psk &psk)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|GeneratePsk|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    // 校验入参
    auto result = ValidatePskParams(pskParam);
    if (result != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|GeneratePsk|END|returnF||validate psk params failed");
        return result;
    }

    // 生成psk凭证key
    std::vector<uint8_t> pskContent(pskParam.pskLength);
    result = GeneratePskContent(pskParam.pskLength, pskContent);
    if (result != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|GeneratePsk|END|returnF||generate psk content failed");
        return result;
    }
    // 创建psk对象
    Psk createPsk;
    BuildPskObj(pskParam, pskContent, createPsk);

    // 构造psk凭证token并加密
    std::vector<std::byte> encryptedPskToken;
    result = BuildAndEncryptPskToken(createPsk, encryptedPskToken);
    if (result != PskManagerRC::OK) {
        memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
        // SetPskContent方法中有安全清除数据的函数调用
        std::vector<uint8_t> emptyContent;
        createPsk.SetPskContent(emptyContent);
        CCSEC_LOG_ERROR("|GeneratePsk|END|returnF||failed to build and encrypt psk token");
        return result;
    }
    // 触发回调对加密psk token存储
    if (TriggerCreatePskCallback(createPsk.GetPskId(), encryptedPskToken) != PskManagerRC::OK) {
        memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
        // SetPskContent方法中有安全清除数据的函数调用
        std::vector<uint8_t> emptyContent;
        createPsk.SetPskContent(emptyContent);
        return PskManagerRC::CALL_BACK_EXECUTE_FAILED;
    }

    // 将psk凭证对象加入内存管理
    pskContentMap_.emplace(createPsk.GetPskContent(), createPsk.GetPskId());
    pskIdMap_.emplace(createPsk.GetPskId(), createPsk);
    curPskMaxId_.fetch_add(1);
    psk = createPsk;

    memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
    // SetPskContent方法中有安全清除数据的函数调用
    std::vector<uint8_t> emptyContent;
    createPsk.SetPskContent(emptyContent);
    CCSEC_LOG_INFO("|GeneratePsk|END|returnS||generate psk success, pskId:" << createPsk.GetPskId());
    return PskManagerRC::OK;
}

PskManagerRC PskManager::ImportPsk(const PskParam &pskParam, const std::vector<uint8_t> &pskContent, Psk &psk)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|ImportPsk|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    // 校验入参
    auto result = ValidatePskParams(pskParam);
    if (result != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|ImportPsk|END|returnF||validate psk params failed");
        return result;
    }
    // 校验pskLength和pskContent长度是否一致
    if (pskParam.pskLength != pskContent.size()) {
        CCSEC_LOG_ERROR("|ImportPsk|END|returnF||invalid pskContent param, "
                        "the length of pskContent and pskLength not equal");
        return PskManagerRC::INVALID_PARAM;
    }

    // 创建psk对象
    Psk createPsk;
    BuildPskObj(pskParam, pskContent, createPsk);

    // 构造psk凭证token并加密
    std::vector<std::byte> encryptedPskToken;
    result = BuildAndEncryptPskToken(createPsk, encryptedPskToken);
    if (result != PskManagerRC::OK) {
        std::vector<uint8_t> emptyContent;
        createPsk.SetPskContent(emptyContent);
        CCSEC_LOG_ERROR("|ImportPsk|END|returnF||failed to build and encrypt psk token");
        return result;
    }

    // 触发回调对加密psk token存储
    if (TriggerCreatePskCallback(createPsk.GetPskId(), encryptedPskToken) != PskManagerRC::OK) {
        std::vector<uint8_t> emptyContent;
        createPsk.SetPskContent(emptyContent);
        return PskManagerRC::CALL_BACK_EXECUTE_FAILED;
    }

    // 将psk凭证对象加入内存管理
    pskContentMap_.emplace(createPsk.GetPskContent(), createPsk.GetPskId());
    pskIdMap_.emplace(createPsk.GetPskId(), createPsk);
    curPskMaxId_.fetch_add(1);
    psk = createPsk;
    std::vector<uint8_t> emptyContent;
    createPsk.SetPskContent(emptyContent);
    CCSEC_LOG_INFO("|ImportPsk|END|returnS||import psk success, pskId:" << createPsk.GetPskId());
    return PskManagerRC::OK;
}

PskManagerRC PskManager::DeletePsk(const uint32_t pskId)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|DeletePsk|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    // 校验psk是否存在
    auto iter = pskIdMap_.find(pskId);
    if (iter == pskIdMap_.end()) {
        CCSEC_LOG_ERROR("|DeletePsk|returnF||pskId:" << pskId << " has not exist");
        return PskManagerRC::PSK_NOT_EXIST;
    }
    // 触发回调删除psk存储
    if (TriggerDeletePskCallback(pskId) != PskManagerRC::OK) {
        return PskManagerRC::CALL_BACK_EXECUTE_FAILED;
    }

    Psk &psk = iter->second;
    // 删除psk map中信息
    pskContentMap_.erase(psk.GetPskContent());
    pskIdMap_.erase(pskId);
    CCSEC_LOG_INFO("|DeletePsk|END|returnS||delete psk success, pskId:" << pskId);
    return PskManagerRC::OK;
}

void PskManager::ClearAllData()
{
    pskContentMap_.clear();
    pskIdMap_.clear();
    curPskMaxId_.store(1);
    options_ = PsKManagerInitOptions{};
}

PskManagerRC PskManager::ValidatePskMetaData(const PskMetaData &pskMeta)
{
    if (pskMeta.pskId > options_.pskMaxCount) {
        CCSEC_LOG_ERROR("|ValidatePskMetaData|END|returnF|curPskMaxId:" << pskMeta.pskId << " reaches limit");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskMeta.issuer.length() < PSK_ISSUER_LENGTH_MIN || pskMeta.issuer.length() > PSK_ISSUER_LENGTH_MAX) {
        CCSEC_LOG_ERROR("|ValidatePskMetaData|END|returnF||length of issuer is invalid: "<< pskMeta.issuer.length()
                        << ", length must in range [" << PSK_ISSUER_LENGTH_MIN << ", " << PSK_ISSUER_LENGTH_MAX <<
                        "].");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskMeta.subject.length() < PSK_SUBJECT_LENGTH_MIN || pskMeta.subject.length() > PSK_SUBJECT_LENGTH_MAX) {
        CCSEC_LOG_ERROR("|ValidatePskMetaData|END|returnF||length of subject is invalid: "<< pskMeta.subject.length()
                        << ", length must in range [" << PSK_SUBJECT_LENGTH_MIN << ", " << PSK_SUBJECT_LENGTH_MAX <<
                        "].");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskMeta.pskLength != PSK_LENGTH_256 && pskMeta.pskLength != PSK_LENGTH_384 &&
        pskMeta.pskLength != PSK_LENGTH_512) {
        CCSEC_LOG_ERROR("|ValidatePskMetaData|END|returnF||pskLength is invalid: "<< pskMeta.pskLength << ", "
                        "pskLength value must in [" << PSK_LENGTH_256 << ", " << PSK_LENGTH_384 << ", " <<
                        PSK_LENGTH_512 << "].");
        return PskManagerRC::INVALID_PARAM;
    }
    if (pskMeta.validDays < PSK_VALID_DAYS_MIN || pskMeta.validDays > PSK_VALID_DAYS_MAX) {
        CCSEC_LOG_ERROR("|ValidatePskMetaData|END|returnF||validDays is invalid: "<< pskMeta.validDays << ", length "
                        "must in range [" << PSK_VALID_DAYS_MIN << ", " << PSK_VALID_DAYS_MAX << "].");
        return PskManagerRC::INVALID_PARAM;
    }
    return PskManagerRC::OK;
}

void PskManager::BuildPskObjWithMetaData(const PskMetaData &pskMeta, const std::vector<uint8_t> &pskContent, Psk &psk)
{
    psk.SetPskId(curPskMaxId_.load());
    psk.SetIssuer(pskMeta.issuer);
    psk.SetSubject(pskMeta.subject);
    psk.SetPskLength(pskMeta.pskLength);
    psk.SetPskContent(pskContent);
    psk.SetValidDays(pskMeta.validDays);
    psk.SetBeginTime(pskMeta.beginTime);
    psk.SetEndTime(pskMeta.endTime);
}

PskManagerRC PskManager::SplitPskToken(const std::vector<std::byte> &pskToken,
                                       std::vector<uint8_t> &pskContent,
                                       std::string &pskMetaJson)
{
    // 将 std::byte 转换为 char 以便处理
    std::string tokenStr(reinterpret_cast<const char*>(pskToken.data()), pskToken.size());

    // 查找分隔符 '.'
    size_t dotPos = tokenStr.find('.');
    if (dotPos == std::string::npos) {
        CCSEC_LOG_ERROR("|SplitPskToken|END|returnF||invalid psk token format, missing separator");
        return PskManagerRC::ERROR;
    }

    // 提取两部分：Base64编码的PSK内容和PSK元数据
    std::string pskContentB64 = tokenStr.substr(0, dotPos);
    std::string pskMetaB64 = tokenStr.substr(dotPos + 1);

    // Base64解码
    try {
        auto decodedContent = Base64Decode(pskContentB64);
        auto decodedMeta = Base64Decode(pskMetaB64);

        // 转换为目标类型
        pskContent.assign(decodedContent.begin(), decodedContent.end());
        pskMetaJson = std::string(decodedMeta.begin(), decodedMeta.end());

        CCSEC_LOG_INFO("|SplitPskToken|END|returnS||split psk token success");
        return PskManagerRC::OK;
    } catch (const std::exception &e) {
        CCSEC_LOG_ERROR("|SplitPskToken|END|returnF||base64 decode failed: %s" << e.what());
        return PskManagerRC::ERROR;
    }
}

PskManagerRC PskManager::ParsePskMetaJsonString(const std::string &pskMetaJson, PskMetaData &pskMetaData)
{
    Document doc;
    doc.Parse(pskMetaJson.c_str());

    if (doc.HasParseError()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||json parse error");
        return PskManagerRC::ERROR;
    }

    if (!doc.IsObject()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid json format, not an object");
        return PskManagerRC::ERROR;
    }
    if (!doc.HasMember("pskId") || !doc["pskId"].IsUint()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid field pskId");
        return PskManagerRC::ERROR;
    }
    if (!doc.HasMember("issuer") || !doc["issuer"].IsString()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid field issuer");
        return PskManagerRC::ERROR;
    }
    if (!doc.HasMember("subject") || !doc["subject"].IsString()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid field subject");
        return PskManagerRC::ERROR;
    }
    if (!doc.HasMember("pskLength") || !doc["pskLength"].IsUint()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid field pskLength");
        return PskManagerRC::ERROR;
    }
    if (!doc.HasMember("validDays") || !doc["validDays"].IsUint()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid field validDays");
        return PskManagerRC::ERROR;
    }
    if (!doc.HasMember("beginTime") || !doc["beginTime"].IsString()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid field beginTime");
        return PskManagerRC::ERROR;
    }
    if (!doc.HasMember("endTime") || !doc["endTime"].IsString()) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid field endTime");
        return PskManagerRC::ERROR;
    }
    std::time_t beginTime;
    if (ParseTime(doc["beginTime"].GetString(), beginTime) != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid beginTime field");
        return PskManagerRC::ERROR;
    }
    std::time_t endTime;
    if (ParseTime(doc["endTime"].GetString(), endTime) != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|ParsePskMetaJsonString|END|returnF||invalid endTime field");
        return PskManagerRC::ERROR;
    }
    pskMetaData.pskId = doc["pskId"].GetUint();
    pskMetaData.issuer = doc["issuer"].GetString();
    pskMetaData.subject = doc["subject"].GetString();
    pskMetaData.pskLength = doc["pskLength"].GetUint();
    pskMetaData.validDays = doc["validDays"].GetUint();
    pskMetaData.beginTime = beginTime;
    pskMetaData.endTime = endTime;
    CCSEC_LOG_INFO("|ParsePskMetaJsonString|END|returnT||parse psk meta json success");
    return PskManagerRC::OK;
}

PskManagerRC PskManager::DecryptAndParsePskToken(const std::string &encryptedPskToken,
                                                 std::vector<uint8_t> &pskContent,
                                                 PskMetaData &pskMetaData)
{
    CCSEC_LOG_INFO("|DecryptAndParsePskToken|START|||decrypt and parse psk token");
    // 1. 解密PSK Token
    std::vector<std::byte> decryptedToken;
    auto result = DecryptPskCiphertext(encryptedPskToken, decryptedToken);
    if (result != PskManagerRC::OK) {
        return result;
    }

    // 2. 拆分PSK Token
    std::string pskMetaJson;
    result = SplitPskToken(decryptedToken, pskContent, pskMetaJson);
    if (result != PskManagerRC::OK) {
        memset_s(decryptedToken.data(), decryptedToken.size(), 0, decryptedToken.size());
        return result;
    }

    // 3. 解析PSK Meta JSON
    result = ParsePskMetaJsonString(pskMetaJson, pskMetaData);
    if (result != PskManagerRC::OK) {
        memset_s(decryptedToken.data(), decryptedToken.size(), 0, decryptedToken.size());
        return result;
    }
    memset_s(decryptedToken.data(), decryptedToken.size(), 0, decryptedToken.size());
    CCSEC_LOG_INFO("|DecryptAndParsePskToken|END|returnS||decrypt and parse psk token success");
    return PskManagerRC::OK;
}

PskManagerRC PskManager::LoadAllPsk(const std::vector<std::string> &pskList)
{
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|LoadAllPsk|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    if (pskList.empty()) {
        CCSEC_LOG_ERROR("|LoadAllPsk|END|returnF||pskList is empty");
        return PskManagerRC::INVALID_PARAM;
    }
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    ClearAllData();
    for (size_t i = 0; i < pskList.size(); ++i) {
        const auto &pskCiphertext = pskList[i];
        if (pskCiphertext.empty()) {
            CCSEC_LOG_ERROR("|LoadAllPsk|END|returnF||pskCiphertext is empty, index: " << i);
            return PskManagerRC::INVALID_PARAM;
        }
        // 解密并拆分pskCiphertext
        std::vector<uint8_t> pskContent;
        PskMetaData pskMetaData;
        auto ret = DecryptAndParsePskToken(pskCiphertext, pskContent, pskMetaData);
        if (ret != PskManagerRC::OK) {
            CCSEC_LOG_ERROR("|LoadAllPsk|END|returnF||pskCiphertext decrypt and parse failed, index: " << i);
            return ret;
        }
        // 校验PskMeta信息
        ret = ValidatePskMetaData(pskMetaData);
        if (ret != PskManagerRC::OK) {
            memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
            CCSEC_LOG_ERROR("|LoadAllPsk|END|returnF||pskMetaData validate failed, index: " << i);
            return ret;
        }
        // 构造psk对象
        Psk psk;
        BuildPskObjWithMetaData(pskMetaData, pskContent, psk);
        // 加入map
        pskContentMap_.insert(std::make_pair(psk.GetPskContent(), psk.GetPskId()));
        pskIdMap_.insert(std::make_pair(psk.GetPskId(), psk));
        curPskMaxId_.fetch_add(1);
        memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
    }

    CCSEC_LOG_INFO("|LoadAllPsk|END|returnS|load all psk success");
    return PskManagerRC::OK;
}


bool isValidPskLength(std::vector<uint8_t> pskContent)
{
    size_t len = pskContent.size();
    if (len > PSK_CONTENT_MAX_LENGTH) {
        return false;
    }
    if (len == PSK_LENGTH_256 || len == PSK_LENGTH_384 ||
        len == PSK_LENGTH_512) {
        return true;
    }
    return false;
}

PskMetaData ConstructPskMetaData(const Psk& psk)
{
    PskMetaData pskMetaData;
    pskMetaData.pskId = psk.GetPskId();
    pskMetaData.issuer = psk.GetIssuer();
    pskMetaData.subject = psk.GetSubject();
    pskMetaData.pskLength = psk.GetPskLength();
    pskMetaData.validDays = psk.GetValidDays();
    pskMetaData.beginTime = psk.GetBeginTime();
    pskMetaData.endTime = psk.GetEndTime();
    return pskMetaData;
}

PskManagerRC PskManager::UpdatePsk(const uint32_t pskId, std::vector<uint8_t> pskContent, Psk &psk)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|UpdatePsk|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    bool isValidPskId = false;
    bool isValidPskContent = false;
    // 检查 pskId 输入规范
    if (pskIdMap_.find(pskId) != pskIdMap_.end()) {
        isValidPskId = true;
    }
    // 检查 pskContent 输入规范
    if (!isValidPskLength(pskContent)) {
        CCSEC_LOG_ERROR("|PskManager::UpdatePsk|Invalid pskContent length");
    }
    if (pskContentMap_.find(pskContent) != pskContentMap_.end()) {
        isValidPskContent = true;
    }
    Psk prePsk;
    // 校验是否存在对应的唯一psk对象
    if (isValidPskId && isValidPskContent) {    // 两个入参同时查出对应psk，若相同则成功更新，不同则入参错误
        if (pskIdMap_.at(pskId).GetPskId() == pskContentMap_.at(pskContent)) {
            prePsk = pskIdMap_.at(pskId);
        } else {
            memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
            CCSEC_LOG_ERROR("|PskManager::UpdatePsk|END|returnF|Inconsistent pskId and pskContent");
            return PskManagerRC::INVALID_PARAM;
        }
    } else if (isValidPskId && !isValidPskContent) {  // 仅pskId有效时，根据pskId获取psk对象
        prePsk = pskIdMap_.at(pskId);
    } else if (!isValidPskId && isValidPskContent) {  // 仅pskContent有效时，若pskContent对应pskId有效，获取psk对象
        uint32_t tempPskId = pskContentMap_.at(pskContent);
        if (pskIdMap_.find(tempPskId) != pskIdMap_.end()) {
            prePsk = pskIdMap_.at(tempPskId);
        } else {
            memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());
            CCSEC_LOG_ERROR("|PskManager::UpdatePsk|END|returnF|pskId in pskContent dont exist");
            return PskManagerRC::INVALID_PARAM;
        }
    } else {  // pskId及pskContent都无效时直接返回
        CCSEC_LOG_ERROR("|PskManager::UpdatePsk|END|returnF|Invalid pskId and pskContent");
        return PskManagerRC::INVALID_PARAM;
    }

    memset_s(pskContent.data(), pskContent.size(), 0, pskContent.size());   // 清除明文秘钥
    pskContent.clear();

    // 生成psk凭证key
    std::vector<uint8_t> newPskContent(prePsk.GetPskLength());
    auto result = GeneratePskContent(prePsk.GetPskLength(), newPskContent);
    if (result != PskManagerRC::OK) {
        std::vector<uint8_t> emptyContent;
        prePsk.SetPskContent(emptyContent);
        CCSEC_LOG_ERROR("|PskManager::UpdatePsk|END|returnF|GeneratePskContent fail");
        return result;
    }

    psk = prePsk;
    // 根据新生成安全随机字符串，当前时间更新psk内容
    psk.SetPskContent(newPskContent);
    psk.SetBeginTime(time(nullptr));
    psk.SetEndTime(psk.GetBeginTime() + psk.GetValidDays() * DAY_TO_SECOND_TIME);  // 转换成秒
    memset_s(newPskContent.data(), newPskContent.size(), 0, newPskContent.size());   // 清除新生成明文秘钥
    newPskContent.clear();

    // 构造psk凭证token并加密
    std::vector<std::byte> encryptedPskToken;
    result = BuildAndEncryptPskToken(psk, encryptedPskToken);
    if (result != PskManagerRC::OK) {
        std::vector<uint8_t> emptyContent;
        prePsk.SetPskContent(emptyContent);
        psk.SetPskContent(emptyContent);
        CCSEC_LOG_ERROR("|PskManager::UpdatePsk|END|returnF|BuildAndEncryptPskToken fail");
        return result;
    }

    // 触发回调更新psk存储
    if (TriggerUpdatePskCallback(psk.GetPskId(), encryptedPskToken) != PskManagerRC::OK) {
        std::vector<uint8_t> emptyContent;
        prePsk.SetPskContent(emptyContent);
        psk.SetPskContent(emptyContent);
        return PskManagerRC::CALL_BACK_EXECUTE_FAILED;
    }

    // 删除未更新的psk对象内存，将更新的psk凭证对象加入内存管理
    auto itPskIdMap = pskIdMap_.find(prePsk.GetPskId());
    if (itPskIdMap != pskIdMap_.end()) {
        pskIdMap_.erase(itPskIdMap);
    }
    auto itPskContentMap = pskContentMap_.find(prePsk.GetPskContent());
    if (itPskContentMap != pskContentMap_.end()) {
        pskContentMap_.erase(itPskContentMap);
    }
    pskIdMap_.insert(std::make_pair(psk.GetPskId(), psk));
    pskContentMap_.insert(std::make_pair(psk.GetPskContent(), psk.GetPskId()));
    std::vector<uint8_t> emptyContent;
    prePsk.SetPskContent(emptyContent);
    CCSEC_LOG_INFO("|PskManager::UpdatePsk|END|returnS|UpdatePsk success, pskId:" << psk.GetPskId());
    return PskManagerRC::OK;
}

PskManagerRC PskManager::GetPsk(const uint32_t pskId, std::vector<uint8_t> &pskContent)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|GetPsk|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    // 检查是否存在对应Psk
    if (pskIdMap_.find(pskId) == pskIdMap_.end()) {
        CCSEC_LOG_ERROR("|PskManager::GetPsk|END|returnS|Psk not exist, pskId:" << pskId);
        return PskManagerRC::PSK_NOT_EXIST;
    }
    pskContent = pskIdMap_.at(pskId).GetPskContent();
    CCSEC_LOG_INFO("|PskManager::GetPsk|END|returnS|GetPsk success, pskId:" << pskId);
    return PskManagerRC::OK;
}

PskManagerRC PskManager::GetPskMetaData(const uint32_t pskId, PskMetaData &pskMetaData)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|GetPskMetaData|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    // 检查是否存在对应Psk
    if (pskIdMap_.find(pskId) == pskIdMap_.end()) {
        CCSEC_LOG_ERROR("|PskManager::GetPskMetaData|END|returnS|Psk not exist, pskId:" << pskId);
        return PskManagerRC::PSK_NOT_EXIST;
    }
    pskMetaData = ConstructPskMetaData(pskIdMap_.at(pskId));
    CCSEC_LOG_INFO("|PskManager::GetPskMetaData|END|returnS|GetPskMetaData success, pskId:" << pskId);
    return PskManagerRC::OK;
}

PskManagerRC PskManager::CheckPskValid(const uint32_t pskId)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|CheckPskValid|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    // 检查是否存在对应Psk
    if (pskIdMap_.find(pskId) == pskIdMap_.end()) {
        CCSEC_LOG_ERROR("|PskManager::CheckPskValid|END|returnS|Psk not exist, pskId:" << pskId);
        return PskManagerRC::PSK_NOT_EXIST;
    }
    // 判断当前时间晚于过期时间
    time_t EndTime = pskIdMap_.at(pskId).GetEndTime();
    if (std::time(nullptr) > EndTime) {
        CCSEC_LOG_INFO("|PskManager::CheckPskValid|END|returnS|Psk has expired, pskId:" << pskId);
        return PskManagerRC::PSK_HAS_EXPIRED;
    }
    CCSEC_LOG_INFO("|PskManager::CheckPskValid|END|returnS|Psk is valid, pskId:" << pskId);
    return PskManagerRC::OK;
}

PskManagerRC PskManager::CheckPskValidAndAutoUpdate(const uint32_t pskId)
{
    std::unique_lock<std::shared_mutex> lock(rwMutex_);
    if (!CheckInited()) {
        CCSEC_LOG_ERROR("|CheckPskValidAndAutoUpdate|END|returnF|psk manager has not been initialized.");
        return PskManagerRC::UNINITED;
    }
    // 检查是否存在对应Psk
    if (pskIdMap_.find(pskId) == pskIdMap_.end()) {
        CCSEC_LOG_ERROR("|PskManager::CheckPskValidAndAutoUpdate|END|returnS|Psk not exist, pskId:" << pskId);
        return PskManagerRC::PSK_NOT_EXIST;
    }
    time_t EndTime = pskIdMap_.at(pskId).GetEndTime();
    if (std::time(nullptr) <= EndTime) {
        CCSEC_LOG_INFO("|PskManager::CheckPskValidAndAutoUpdate|END|returnS|Psk is valid, pskId:" << pskId);
        return PskManagerRC::OK;
    }
    lock.unlock();
    Psk psk;
    auto ret = UpdatePsk(pskId, {}, psk);
    if (ret != PskManagerRC::OK) {
        CCSEC_LOG_ERROR("|PskManager::CheckPskValidAndAutoUpdate|END|Psk has expired but update fail, pskId:"
                        << pskId);
    }
    CCSEC_LOG_INFO("|PskManager::CheckPskValidAndAutoUpdate|END|returnS|Psk has update success, pskId:"
                   << pskId);
    std::vector<uint8_t> emptyContent;
    psk.SetPskContent(emptyContent);
    return PskManagerRC::PSK_HAS_EXPIRED;
}

}  // namespace cdf
