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

#include "cdf/modules/key_management/openbao/openbao_key_manager.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "securec.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/cryption/native_cryptor.h"
#include "cdf/modules/key_management/openbao/openbao_utils.h"
#include "cdf/utils/base64.h"
#include "cdf/utils/file_utils.h"

#ifdef __cplusplus
extern "C" {
cdf::OpenbaoKeyManager *BorrowOpenbaoKeyManager()
{
    auto &singleton = cdf::OpenbaoKeyManager::GetInstance();
    return &singleton;
}
}
#endif

namespace cdf {

namespace {
constexpr uint32_t DOMAINID_MAX = 1023;
constexpr uint32_t MAX_KEY_COUNT = 1023;
constexpr uint32_t DOMAINID_MIN = 2;
constexpr uint32_t DAY_TO_TIME = 24 * 60 * 60;
constexpr uint32_t OPENBAO_MAX_MASTER_KEY_VALID_TIME_IN_DAYS = 5 * 365;
constexpr uint32_t OPENBAO_MAX_MASTER_KEY_VALID_TIME = OPENBAO_MAX_MASTER_KEY_VALID_TIME_IN_DAYS * DAY_TO_TIME;

using OpenBaoCheckSymAlg = EnumCheck<CryptoSymAlg, CryptoSymAlg::AES256_GCM, CryptoSymAlg::CHACHA20_POLY1305>;

constexpr uint8_t VERSION_INDEX = 0;
constexpr uint8_t SYMALG_INDEX = 1;
constexpr uint8_t DOMAINID_INDEX = 2;
constexpr uint8_t KEYID_INDEX = 4;
constexpr uint8_t MAX_INDEX = 6;
} // namespace
KeyManagerRC OpenbaoKeyManager::UnInit()
{
    accessToken_.clear();
    domainKeyMap_.clear();
    domainCount_ = DOMAINID_MIN;
    inited_ = false;
    if (type_ == KeyManagerTy::OPENBAO) {
        CCSEC_LOG_INFO("KeyManager::UnInit|END|returnS|openbao uninit success.");
    } else if (type_ == KeyManagerTy::VAULT) {
        CCSEC_LOG_INFO("KeyManager::UnInit|END|returnS|vault uninit success.");
    }
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::PrepareMap()
{
    std::map<uint32_t, std::map<uint32_t, int64_t>> ret;
    std::ostringstream cmd;
    cmd << exePath_ << " list -format=json transit/keys";

    auto [rc, result] = RunCommandAndGetResult(exePath_, MakeStringView(accessToken_), cmd.str());
    if (rc != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("|KeyManager::PrepareMap|END|returnF||Failed to prepare map");
        return KeyManagerRC::ERROR;
    }

    // HACK all result empty
    if (result == "{}\n") {
        return KeyManagerRC::OK;
    }

    std::vector<std::pair<uint32_t, uint32_t>> pairs;
    rc = GetJsonFieldIntPairVec(result, pairs);
    if (rc != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("|KeyManager::PrepareMap|END|returnF||Failed to GetJsonFieldIntPairVec");
        return KeyManagerRC::ERROR;
    }

    for (const auto &pair : pairs) {
        std::ostringstream tmpCmd;
        tmpCmd << exePath_ << " read -format=json transit/keys/CDF" << pair.first << "_Key" << pair.second;
        std::tie(rc, result) = RunCommandAndGetResult(exePath_, MakeStringView(accessToken_), tmpCmd.str());

        if (rc != KeyManagerRC::OK) {
            CCSEC_LOG_ERROR("|KeyManager::PrepareMap|END|returnF||Failed to read key info");
            return KeyManagerRC::ERROR;
        }
        if (result.empty()) {
            return KeyManagerRC::OK;
        }
        int time = GetJsonFieldMaxInt(result);
        if (time != -1) {
            if (domainKeyMap_.find(pair.first) == domainKeyMap_.end()) {
                domainKeyMap_.insert({pair.first, std::map<uint32_t, int64_t>()});
            }
            domainKeyMap_[pair.first].insert({pair.second, time});
        } else {
            domainKeyMap_.clear();
            CCSEC_LOG_ERROR("|KeyManager::PrepareMap|END|returnF||Failed to GetJsonFieldMaxInt, " << result);
            return KeyManagerRC::ERROR;
        }
    }
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::Init(std::string_view exePath, std::string_view accessToken, uint32_t domainCount)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (CheckInited()) {
        CCSEC_LOG_WARN("|KeyManager::Init||KeyManager has already been inited, new init process has been ignored.");
        return KeyManagerRC::OK;
    }

    // check openbao binary path
    std::string exeRealPath(exePath);
    std::string errMsg;
    if (!FileUtils::CanonicalPath(exeRealPath) || !FileUtils::CheckUserAccess(exeRealPath, (R_OK | X_OK))) {
        CCSEC_LOG_ERROR("|KeyManager::Init|returnF|Invalid bianry path, or missing read & execute permission: "
                        << exePath << ". " << errMsg);
        return KeyManagerRC::INVALID_PARAM;
    }
    exePath_ = exeRealPath;

    // check domain count
    if (domainCount < DOMAINID_MIN || domainCount > DOMAINID_MAX) {
        CCSEC_LOG_ERROR("|KeyManager::Init|returnF|Invalid domain count: "
                        << domainCount << ", must in range [" << DOMAINID_MIN << ", " << DOMAINID_MAX << "].");
        return KeyManagerRC::DOMAIN_COUNT_INVALID;
    }

    // We don't allow empty access token
    if (accessToken.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::Init|END|returnF||Failed to continue, accessToken is empty.");
        return KeyManagerRC::ERROR;
    }

    (void)memset_s(accessToken_.data(), accessToken_.size(), 0, accessToken_.size()); // clear old data
    accessToken_.resize(accessToken.size());
    if (memcpy_s(accessToken_.data(), accessToken_.size(), accessToken.data(), accessToken_.size()) != EOK) {
        accessToken_.resize(0);
        CCSEC_LOG_ERROR("|KeyManager::Init|END|returnF||memcpy failed.");
        return KeyManagerRC::ERROR;
    }

    // Prepare map
    auto rc = PrepareMap();
    if (rc != KeyManagerRC::OK) {
        return KeyManagerRC::ERROR;
    }

    if (type_ == KeyManagerTy::OPENBAO) {
        CCSEC_LOG_INFO("KeyManager::Init|END|returnS|openbao init success.");
    } else if (type_ == KeyManagerTy::VAULT) {
        CCSEC_LOG_INFO("KeyManager::Init|END|returnS|vault init success.");
    }

    // inited success
    inited_ = true;
    domainCount_ = domainCount;
    return KeyManagerRC::OK;
}

std::pair<KeyManagerRC, uint32_t> OpenbaoKeyManager::GenerateKeyId(uint32_t domainId)
{
    uint32_t keyId = 0;
    uint32_t size = domainKeyMap_[domainId].size();
    if (size >= MAX_KEY_COUNT) {
        CCSEC_LOG_ERROR("|KeyManager::GenerateKeyId|END|returnF||The key in the domain is full.");
        return {KeyManagerRC::INVALID_PARAM, 0};
    }
    if (size != 0) {
        auto maxId = domainKeyMap_[domainId].rbegin()->first;
        if (maxId >= UINT16_MAX) {
            CCSEC_LOG_ERROR(
                "|KeyManager::GenerateKeyId|END|returnF||The keyId is exhausted and the domain needs to be emptied.");
            return {KeyManagerRC::INVALID_PARAM, 0};
        }
        keyId = domainKeyMap_[domainId].rbegin()->first + 1;
    }
    return {KeyManagerRC::OK, keyId};
}

std::pair<KeyManagerRC, uint32_t> OpenbaoKeyManager::CreateKey(uint32_t domainId)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto validateRet = ValidateDomain(domainId);
    if (validateRet != KeyManagerRC::OK) {
        return {validateRet, 0};
    }

    // 判断size，如果为0，ID从0开始取；如果非0，反向取最大值作为maxID,后续如果有新增，maxID + 1
    auto keyIdResult = GenerateKeyId(domainId);
    if (keyIdResult.first != KeyManagerRC::OK) {
        return keyIdResult;
    }
    uint32_t keyId = keyIdResult.second;

    // make command string and execute
    std::ostringstream cmd1;
    cmd1 << exePath_ << " write -f transit/keys/CDF" << domainId << "_Key" << keyId;
    std::ostringstream cmd2;
    cmd2 << exePath_ << " write transit/keys/CDF" << domainId << "_Key" << keyId
         << "/config exportable=true deletion_allowed=true";

    auto ret = RunCommandAndCheck(exePath_, MakeStringView(accessToken_), cmd1.str());
    if (ret != KeyManagerRC::OK) {
        return {KeyManagerRC::ERROR, 0};
    }
    ret = RunCommandAndCheck(exePath_, MakeStringView(accessToken_), cmd2.str());
    if (ret != KeyManagerRC::OK) {
        return {KeyManagerRC::ERROR, 0};
    }

    std::ostringstream tmpCmd;
    tmpCmd << exePath_ << " read -format=json transit/keys/CDF" << domainId << "_Key" << keyId;
    auto [rc, result] = RunCommandAndGetResult(exePath_, MakeStringView(accessToken_), tmpCmd.str());
    if (rc != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("|KeyManager::PrepareMap|END|returnF||Failed to read key info");
        return {KeyManagerRC::ERROR, 0};
    }

    // On success, store the createkey time
    int time = GetJsonFieldMaxInt(result);
    if (time == -1) {
        CCSEC_LOG_ERROR("|KeyManager::CreateKey|END|returnF||Fail to get key create time.");
        ret = RemoveKey(domainId, keyId);
        if (ret != KeyManagerRC::OK) {
            return {KeyManagerRC::ERROR, 0};
        }
        return {KeyManagerRC::ERROR, 0};
    }
    if (domainKeyMap_.find(domainId) == domainKeyMap_.end()) {
        domainKeyMap_.insert({domainId, std::map<uint32_t, int64_t>()});
    }
    domainKeyMap_[domainId].insert({keyId, time});
    CCSEC_LOG_INFO("KeyManager::CreateKey|END|returnS|create key success, domainId:" << domainId
                                                                                     << ", keyId:" << keyId);
    return {KeyManagerRC::OK, keyId};
}

KeyManagerRC OpenbaoKeyManager::DisplayKey(uint32_t domainId) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!inited_) {
        CCSEC_LOG_ERROR("|KeyManager::DisplayKey|END|returnF||KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }

    if (domainId >= domainCount_) {
        CCSEC_LOG_ERROR("KeyManager::DisplayKey|END|returnF|Invalid domain id:"
                        << domainId << " is larger than or equal to current domainCount :" << domainCount_);
        return KeyManagerRC::INVALID_PARAM;
    }

    if (domainKeyMap_.empty() || domainKeyMap_.find(domainId) == domainKeyMap_.end()) {
        CCSEC_LOG_WARN("|KeyManager::DisplayKey|END|||no key matches");
        std::cout << "no key matches" << std::endl;
        return KeyManagerRC::OK;
    }

    auto it = domainKeyMap_.find(domainId);
    std::string accessToken = std::string(accessToken_.begin(), accessToken_.end());
    for (const auto &innerPair : it->second) {
        std::cout << "[domainId: " << domainId << ", keyId: " << innerPair.first
                  << ", status: active, createTime: " << innerPair.second
                  << ", expireTime: " << innerPair.second + OPENBAO_MAX_MASTER_KEY_VALID_TIME << "]\n";
    }
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::DisplayAllKey() const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!inited_) {
        CCSEC_LOG_ERROR("|KeyManager::DisplayAllKey|END|returnF||KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }

    if (domainKeyMap_.empty()) {
        CCSEC_LOG_WARN("|KeyManager::DisplayAllKey|END|||no key matches");
        std::cout << "no key matches." << std::endl;
        return KeyManagerRC::OK;
    }

    std::string accessToken = std::string(accessToken_.begin(), accessToken_.end());
    for (const auto &pair : domainKeyMap_) {
        for (const auto &innerPair : pair.second) {
            std::cout << "[domainId: " << pair.first << ", keyId: " << innerPair.first
                      << ", status: active, createTime: " << innerPair.second
                      << ", expireTime: " << innerPair.second + OPENBAO_MAX_MASTER_KEY_VALID_TIME << "]\n";
        }
    }
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::RemoveKey(uint32_t domainId, uint32_t keyId)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (!inited_) {
        CCSEC_LOG_ERROR("|KeyManager::RemoveKey|END|returnF||KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }
    if (domainKeyMap_.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::RemoveKey|END|returnF||no keys");
        return KeyManagerRC::ERROR;
    }
    if (domainId >= domainCount_) {
        CCSEC_LOG_ERROR("KeyManager::RemoveKey|END|returnF|Invalid domain id:"
                        << domainId << " is larger than or equal to current domainCount :" << domainCount_);
        return KeyManagerRC::INVALID_PARAM;
    }

    if (keyId > UINT16_MAX) {
        CCSEC_LOG_ERROR("KeyManager::RemoveKey|END|returnF|Invalid key id:" << keyId
                                                                            << " is larger than max key id 65535");
        return KeyManagerRC::INVALID_PARAM;
    }
    auto domainIt = domainKeyMap_.find(domainId);
    if (domainIt == domainKeyMap_.end()) {
        CCSEC_LOG_ERROR("KeyManager::RemoveKey|END|returnF|The domainId:" << domainId << " could not be found.");
        return KeyManagerRC::INVALID_PARAM;
    } else {
        auto subMap = domainIt->second;
        if (subMap.find(keyId) == subMap.end()) {
            CCSEC_LOG_ERROR("KeyManager::RemoveKey|END|returnF|The keyId:" << keyId << " could not be found.");
            return KeyManagerRC::INVALID_PARAM;
        }
    }

    std::ostringstream cmd;
    cmd << exePath_ << " delete transit/keys/CDF" << domainId << "_Key" << keyId;
    auto ret = RunCommandAndCheck(exePath_, MakeStringView(accessToken_), cmd.str());
    if (ret != KeyManagerRC::OK) {
        return KeyManagerRC::ERROR;
    }

    // remove key from map
    std::map<uint32_t, int64_t> &innerMap = domainKeyMap_[domainId];
    innerMap.erase(keyId);

    // if innerMap is empty, it's okay to remove all keys in this domainId
    if (innerMap.empty()) {
        domainKeyMap_.erase(domainId);
    }

    CCSEC_LOG_INFO("KeyManager::RemoveKey|END|returnS|remove key success.");
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::DeleteAllKey()
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (!inited_) {
        CCSEC_LOG_ERROR("|KeyManager::DeleteAllKey|END|returnF||KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }
    if (domainKeyMap_.empty()) {
        CCSEC_LOG_WARN("|KeyManager::DeleteAllKey|END|||no keys");
        return KeyManagerRC::OK;
    }

    for (auto outerIt = domainKeyMap_.begin(); outerIt != domainKeyMap_.end();) {
        for (auto innerIt = outerIt->second.begin(); innerIt != outerIt->second.end();) {
            std::ostringstream cmd;
            cmd << exePath_ << " delete transit/keys/CDF" << outerIt->first << "_Key" << innerIt->first;
            auto ret = RunCommandAndCheck(exePath_, MakeStringView(accessToken_), cmd.str());
            if (ret != KeyManagerRC::OK) {
                CCSEC_LOG_WARN("KeyManager::DeleteAllKey|||delete keyId:" << innerIt->first << " in domainId:"
                                                                          << outerIt->first << " failed.");
                ++outerIt; // NOTE do not try, move to next
                continue;
            }
            // 删除当前keyId
            innerIt = outerIt->second.erase(innerIt);
        }
        // 删除当前domainId
        if (outerIt->second.empty()) {
            outerIt = domainKeyMap_.erase(outerIt);
        } else {
            ++outerIt;
        }
    }

    if (!domainKeyMap_.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::DeleteAllKey|END|returnF||Failed to delete all keys.");
        return KeyManagerRC::ERROR;
    }

    CCSEC_LOG_INFO("KeyManager::DeleteAllKey|END|returnS|delete all key success.");
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::CheckDomainKeysExpired(uint32_t domainId, uint32_t lead)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::time_t time = std::time(nullptr);
    if (time == static_cast<std::time_t>(-1)) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpired|END|returnF||Fail to get key create time.");
        return KeyManagerRC::ERROR;
    }
    if (!inited_) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpired|END|returnF||KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }
    if (domainKeyMap_.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpired|END|returnF||no keys");
        return KeyManagerRC::ERROR;
    }
    if (domainId >= domainCount_) {
        CCSEC_LOG_ERROR("KeyManager::CheckDomainKeysExpired|END|returnF|Invalid domain id:"
                        << domainId << " is larger than or equal to current domainCount :" << domainCount_);
        return KeyManagerRC::INVALID_PARAM;
    }
    auto it = domainKeyMap_.find(domainId);
    if (it == domainKeyMap_.end()) {
        CCSEC_LOG_ERROR("KeyManager::CheckDomainKeysExpired|END|returnF|The domainId:" << domainId
                                                                                       << " could not be found.");
        return KeyManagerRC::INVALID_PARAM;
    }

    // 检查 lead 是否会导致溢出
    if (lead > UINT32_MAX / DAY_TO_TIME) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpired|END|returnF||"
                        "The lead is too large and would cause overflow.");
        return KeyManagerRC::INVALID_PARAM;
    }

    if (lead > OPENBAO_MAX_MASTER_KEY_VALID_TIME_IN_DAYS || lead * DAY_TO_TIME > OPENBAO_MAX_MASTER_KEY_VALID_TIME) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpired|END|returnF||The lead is invalid.");
        return KeyManagerRC::INVALID_PARAM;
    }

    auto testTime = static_cast<uint32_t>(time) + lead * DAY_TO_TIME;
    bool foundValidKey = false;
    for (const auto &innerPair : it->second) {
        if (innerPair.second + OPENBAO_MAX_MASTER_KEY_VALID_TIME > testTime) {
            foundValidKey = true;
        }
    }

    if (!foundValidKey) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpired|END|returnF||key is expired.");
        return KeyManagerRC::KEY_EXPIRED;
    }

    CCSEC_LOG_INFO("KeyManager::CheckDomainKeysExpired|END|returnS|domain keys are ok.");
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::CheckDomainKeysExpiredParams(uint32_t domainId, uint32_t lead)
{
    if (!inited_) {
        CCSEC_LOG_ERROR("KeyManager::CheckDomainKeysExpiredParams|END|returnF|KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }
    if (domainKeyMap_.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpiredParams|END|returnF||no keys");
        return KeyManagerRC::ERROR;
    }
    if (domainId >= domainCount_) {
        CCSEC_LOG_ERROR("KeyManager::CheckDomainKeysExpiredParams|END|returnF|Invalid domain id:"
                        << domainId << " is larger than or equal to current domainCount :" << domainCount_);
        return KeyManagerRC::INVALID_PARAM;
    }
    if (domainKeyMap_.find(domainId) == domainKeyMap_.end()) {
        CCSEC_LOG_ERROR("KeyManager::CheckDomainKeysExpiredParams|END|returnF|The domainId:" << domainId
                                                                                             << " could not be found.");
        return KeyManagerRC::INVALID_PARAM;
    }

    // 检查 lead 是否会导致溢出
    if (lead > UINT32_MAX / DAY_TO_TIME) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpired|END|returnF||"
                        "The lead is too large and would cause overflow.");
        return KeyManagerRC::INVALID_PARAM;
    }

    if (lead * DAY_TO_TIME > OPENBAO_MAX_MASTER_KEY_VALID_TIME) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpiredParams|END|returnF||The lead is invalid.");
        return KeyManagerRC::INVALID_PARAM;
    }
    return KeyManagerRC::OK;
}

void LogExpiredKeys([[maybe_unused]] const uint32_t domainId, const std::vector<uint32_t> &keyVec)
{
    if (keyVec.empty()) {
        CCSEC_LOG_INFO("KeyManager::LogExpiredKeys|END|returnS|no key expired.");
    } else {
        std::string keyIdStr;
        for (auto keyId : keyVec) {
            keyIdStr += std::to_string(keyId) + ",";
        }
        keyIdStr.erase(keyIdStr.end() - 1);
        CCSEC_LOG_INFO("KeyManager::LogExpiredKeys|END|returnS|domainId:"
                       << domainId << ", keyId:" << keyIdStr << " update successfully.");
    }
}

KeyManagerRC OpenbaoKeyManager::HandleCommand(uint32_t domainId, uint32_t keyId)
{
    std::ostringstream cmd1;
    cmd1 << exePath_ << " delete transit/keys/CDF" << domainId << "_Key" << keyId;
    std::ostringstream cmd2;
    cmd2 << exePath_ << " write -f transit/keys/CDF" << domainId << "_Key" << keyId;
    std::ostringstream cmd3;
    cmd3 << exePath_ << " write transit/keys/CDF" << domainId << "_Key" << keyId
         << "/config deletion_allowed=true";

    // remove expired key
    auto ret = RunCommandAndCheck(exePath_, MakeStringView(accessToken_), cmd1.str());
    if (ret != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("OpenbaoKeyManager::HandleCommand|END|returnF|Fail to run delete command.");
        return KeyManagerRC::ERROR;
    }

    // re-generate key
    ret = RunCommandAndCheck(exePath_, MakeStringView(accessToken_), cmd2.str());
    if (ret != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("OpenbaoKeyManager::HandleCommand|END|returnF|Fail to run create command.");
        return KeyManagerRC::ERROR;
    }

    // allow remove expired key
    ret = RunCommandAndCheck(exePath_, MakeStringView(accessToken_), cmd3.str());
    if (ret != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR(
            "OpenbaoKeyManager::HandleCommand|END|returnF|Fail to run write config command.");
        return KeyManagerRC::ERROR;
    }
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::CheckDomainKeysExpiredAndAutoUpdate(uint32_t domainId, uint32_t lead)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::time_t time = std::time(nullptr);
    if (time == static_cast<std::time_t>(-1)) {
        CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpiredAndAutoUpdate|END|returnF||Fail to get time.");
        return KeyManagerRC::ERROR;
    }
    auto err = CheckDomainKeysExpiredParams(domainId, lead);
    if (err != KeyManagerRC::OK) {
        return err;
    }
    auto it = domainKeyMap_.find(domainId);

    std::vector<uint32_t> keyVec;
    for (const auto &innerPair : it->second) {
        // 检查 innerPair.second + OPENBAO_MAX_MASTER_KEY_VALID_TIME 是否溢出
        if (innerPair.second > INT64_MAX - OPENBAO_MAX_MASTER_KEY_VALID_TIME) {
            CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpiredAndAutoUpdate|END|returnF||uint64 overflow.");
            return KeyManagerRC::ERROR;
        }
        // 检查 static_cast<uint32_t>(time) + lead * DAY_TO_TIME 是否溢出
        if (lead * DAY_TO_TIME > UINT32_MAX - static_cast<uint32_t>(time)) {
            CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpiredAndAutoUpdate|END|returnF||uint32 overflow.");
            return KeyManagerRC::ERROR;
        }
        if (innerPair.second + OPENBAO_MAX_MASTER_KEY_VALID_TIME <= static_cast<uint32_t>(time) + lead * DAY_TO_TIME) {
            auto ret = HandleCommand(domainId, innerPair.first);
            if (ret != KeyManagerRC::OK) {
                return ret;
            }
            std::ostringstream tmpCmd;
            tmpCmd << exePath_ << " read -format=json transit/keys/CDF" << domainId << "_Key" << innerPair.first;
            auto [rc, result] = RunCommandAndGetResult(exePath_, MakeStringView(accessToken_), tmpCmd.str());
            if (rc != KeyManagerRC::OK) {
                CCSEC_LOG_ERROR("|KeyManager::PrepareMap|END|returnF||Failed to read key info");
                return KeyManagerRC::ERROR;
            }

            int timeTmp = GetJsonFieldMaxInt(result);
            if (timeTmp == -1) {
                CCSEC_LOG_ERROR("|KeyManager::CheckDomainKeysExpiredAndAutoUpdate|END|returnF||Fail to get key "
                                "create time.");
                return KeyManagerRC::ERROR;
            }
            domainKeyMap_[domainId][innerPair.first] = timeTmp;
            keyVec.push_back(innerPair.first);
        }
    }
    LogExpiredKeys(domainId, keyVec);
    return KeyManagerRC::OK;
}

KeyManagerRC OpenbaoKeyManager::CheckEncryptAndDecryptParams(uint32_t domainId, const CryptoSymAlg &symAlg)
{
    if (!inited_) {
        CCSEC_LOG_ERROR("|KeyManager::CheckEncryptAndDecryptParams|END|returnF||KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }
    if (domainKeyMap_.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::CheckEncryptAndDecryptParams|END|returnF||no keys");
        return KeyManagerRC::ERROR;
    }
    if (domainId >= domainCount_) {
        CCSEC_LOG_ERROR("KeyManager::CheckEncryptAndDecryptParams|END|returnF|Invalid domain id:"
                        << domainId << " is larger than or equal to current domainCount :" << domainCount_);
        return KeyManagerRC::INVALID_PARAM;
    }
    if (domainKeyMap_.find(domainId) == domainKeyMap_.end()) {
        CCSEC_LOG_ERROR("|KeyManager::CheckEncryptAndDecryptParams|END|returnF|The domainId:"
                        << domainId << " could not be found.");
        return KeyManagerRC::INVALID_PARAM;
    }

    if (!OpenBaoCheckSymAlg::IsValue(symAlg)) {
        CCSEC_LOG_ERROR("|KeyManager::CheckEncryptAndDecryptParams|END|returnF||Invalid crypto symmetric algorithm: "
                        << static_cast<int>(symAlg));
        return KeyManagerRC::INVALID_PARAM;
    }
    return KeyManagerRC::OK;
}

std::vector<std::byte> OpenbaoKeyManager::GetLatestKey(uint32_t domainId, uint32_t &keyId)
{
    if (ValidateDomain(domainId) != KeyManagerRC::OK) {
        return {};
    }
    if (domainKeyMap_.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::GetLatestKey|END|returnF||no keys");
        return {};
    }
    // 获取domanid的最后一个密钥
    auto &keyMap = domainKeyMap_[domainId];
    if (keyMap.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::GetLatestKey|END|returnF||The domainId:" << domainId << " could not be found.");
        return {};
    }
    auto firstKey = keyMap.rbegin();
    keyId = firstKey->first;
    std::ostringstream cmdVec;
    cmdVec << exePath_ << " read transit/export/encryption-key/CDF" << domainId << "_Key" << keyId
           << " -format=json";

    auto [rc, result] = RunCommandAndGetResult(exePath_, MakeStringView(accessToken_), cmdVec.str());
    if (rc != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("|KeyManager::GetLatestKey|END|returnF||Failed to get key for domain " << domainId << ".");
        (void)memset_s(result.data(), result.size(), 0, result.size());
        return {};
    }

    std::string decodeKeystr = GetJsonFieldAsStr(result);
    if (decodeKeystr.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::GetLatestKey|END|returnF||Failed to GetLatestKey for domain "
                        << domainId << ", key " << keyId << ".");
        (void)memset_s(result.data(), result.size(), 0, result.size());
        return {};
    }

    std::string_view decodeKey(decodeKeystr);
    auto key = Base64Decode(decodeKey);
    if (key.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::GetLatestKey|END|returnF||Base64 decode error from key");
        (void)memset_s(result.data(), result.size(), 0, result.size());
        (void)memset_s(decodeKeystr.data(), decodeKeystr.size(), 0, decodeKeystr.size());
        return {};
    }

    std::vector<std::byte> keyVec(reinterpret_cast<std::byte *>(key.data()),
                                  reinterpret_cast<std::byte *>(key.data() + key.size()));

    (void)memset_s(result.data(), result.size(), 0, result.size());
    (void)memset_s(decodeKeystr.data(), decodeKeystr.size(), 0, decodeKeystr.size());
    (void)memset_s(key.data(), key.size(), 0, key.size());
    return keyVec;
}

KeyManagerRC OpenbaoKeyManager::ValidateDomain(const uint32_t domainId) const
{
    if (!inited_) {
        CCSEC_LOG_ERROR("|KeyManager::ValidateDomain|END|returnF|KeyManager is not inited!");
        return KeyManagerRC::UNINITED;
    }
    if (domainId >= domainCount_) {
        CCSEC_LOG_ERROR("|KeyManager::ValidateDomain|END|returnF|Invalid domain id:"
                        << domainId << " is larger than or equal to current domainCount :" << domainCount_);
        return KeyManagerRC::INVALID_PARAM;
    }
    return KeyManagerRC::OK;
}

std::vector<std::byte> ConstructCipherHeader(const CryptoSymAlg &symAlg, uint32_t domainId, uint32_t keyId)
{
    std::vector<std::byte> header(MAX_INDEX);
    // 版本号
    header[VERSION_INDEX] = std::byte{static_cast<std::byte>(1)}; // 当前版本为1

    // 存储算法
    header[SYMALG_INDEX] = std::byte{static_cast<std::byte>(symAlg)};

    // 存储domainId
    header[DOMAINID_INDEX] = std::byte{static_cast<std::byte>((domainId >> 8) & 0xFF)}; // 存储第8-15位
    header[DOMAINID_INDEX + 1] = std::byte{static_cast<std::byte>(domainId & 0xFF)};    // 存储第0-7位

    // 存储keyId
    header[KEYID_INDEX] = std::byte{static_cast<std::byte>((keyId >> 8) & 0xFF)}; // 存储第8-15位
    header[KEYID_INDEX + 1] = std::byte{static_cast<std::byte>(keyId & 0xFF)};    // 存储第0-7位
    return header;
}

std::pair<KeyManagerRC, std::vector<std::byte>> OpenbaoKeyManager::Encrypt(const CryptoSymAlg &symAlg,
                                                                           uint32_t domainId,
                                                                           std::string_view plaintext)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto err = CheckEncryptAndDecryptParams(domainId, symAlg);
    if (err != KeyManagerRC::OK) {
        return {err, {}};
    }
    if (plaintext.empty() || plaintext.size() >= PLAINTEXT_MAX_LENGTH) {
        CCSEC_LOG_ERROR("|Encrypt|END|returnF||Invalid param plaintext");
        return {KeyManagerRC::INVALID_PARAM, {}};
    }
    uint32_t keyId = 0;
    auto keyVec = GetLatestKey(domainId, keyId);
    // if no key found in the domain, manually create a key
    if (keyVec.empty()) {
        if (CreateKey(domainId).first != KeyManagerRC::OK) {
            return {KeyManagerRC::ERROR, {}};
        }
        keyVec = GetLatestKey(domainId, keyId);
    }
    NativeCryptor cryptor;
    std::vector<std::byte> text;
    for (char c : plaintext) {
        text.push_back(ToByte(c));
    }
    auto header = ConstructCipherHeader(symAlg, domainId, keyId);

    auto ret = cryptor.Encrypt(symAlg, text, keyVec);
    (void)memset_s(text.data(), text.size(), 0, text.size());
    (void)memset_s(keyVec.data(), keyVec.size(), 0, keyVec.size());
    if (ret.first != CryptionRC::OK) {
        CCSEC_LOG_ERROR("|KeyManager::Encrypt|END|returnF||Failed to native decrypt.");
        return {KeyManagerRC::ERROR, {}};
    }
    header.insert(header.end(), ret.second.begin(), ret.second.end());
    ret.second.clear();
    // base64 encode ciphertext
    auto ciphertextBase64 = Base64Encode(reinterpret_cast<char *>(header.data()), header.size());
    header.clear();

    CCSEC_LOG_INFO("KeyManager::Encrypt|END|returnS|encrypt success.");
    return {KeyManagerRC::OK, ciphertextBase64};
}

std::vector<std::byte> OpenbaoKeyManager::VaultDecrypt(const CryptoSymAlg &symAlg, uint32_t domainId, uint32_t keyId,
                                                       std::string_view ciphertext)
{
    std::ostringstream cmd;
    cmd << exePath_ << " read transit/export/encryption-key/CDF" << domainId << "_Key" << keyId << " -format=json";

    auto [rc, result] = RunCommandAndGetResult(exePath_, MakeStringView(accessToken_), cmd.str());
    if (rc != KeyManagerRC::OK) {
        (void)memset_s(result.data(), result.size(), 0, result.size());
        return {};
    }
    std::string decodeKeystr = GetJsonFieldAsStr(result);
    (void)memset_s(result.data(), result.size(), 0, result.size());
    if (decodeKeystr.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::Decrypt|END|returnF||Failed to GetOpenbaoLastKeyAsStr.");
        return {};
    }
    std::string_view decodeKey(decodeKeystr);
    auto key = Base64Decode(decodeKey);
    if (key.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::Decrypt|END|returnF||Base64 decode error from key");
        (void)memset_s(decodeKeystr.data(), decodeKeystr.size(), 0, decodeKeystr.size());
        return {};
    }
    std::vector<std::byte> keyVec;
    keyVec.reserve(key.size());
    for (unsigned char i : key) {
        keyVec.push_back(ToByte(i));
    }

    NativeCryptor cryptor;
    std::vector<std::byte> text;
    for (char c : ciphertext) {
        text.push_back(ToByte(c));
    }

    auto ret = cryptor.Decrypt(symAlg, text, keyVec);
    (void)memset_s(decodeKeystr.data(), decodeKeystr.size(), 0, decodeKeystr.size());
    (void)memset_s(text.data(), text.size(), 0, text.size());
    (void)memset_s(keyVec.data(), keyVec.size(), 0, keyVec.size());
    (void)memset_s(key.data(), key.size(), 0, key.size());
    if (ret.first != CryptionRC::OK) {
        CCSEC_LOG_ERROR("|KeyManager::Decrypt|END|returnF||Failed to native decrypt.");
        return {};
    }
    return ret.second;
}

KeyManagerRC OpenbaoKeyManager::ParseCipherHeader(std::vector<unsigned char> cipherHeader, CryptoSymAlg &symAlg,
                                                  uint32_t &domainId, uint32_t &keyId)
{
    if (cipherHeader.size() <= MAX_INDEX) {
        CCSEC_LOG_ERROR("ParseCipherHeader|END|returnF|Invalid param ciphertext length");
        return KeyManagerRC::INVALID_PARAM;
    }
    uint8_t version = static_cast<uint8_t>(cipherHeader[VERSION_INDEX]);
    if (version != 1) { // 当前版本为1
        CCSEC_LOG_ERROR("ParseCipherHeader|END|returnF|Invalid param version");
        return KeyManagerRC::INVALID_PARAM;
    }

    // 获取keyId
    symAlg = static_cast<CryptoSymAlg>(cipherHeader[SYMALG_INDEX]);

    // 获取domainId
    domainId = (static_cast<uint32_t>(cipherHeader[DOMAINID_INDEX]) << 8) | // 取出第8-15位
               static_cast<uint32_t>(cipherHeader[DOMAINID_INDEX + 1]);     // 取出第0-7位

    // 获取algType
    keyId = (static_cast<uint32_t>(cipherHeader[KEYID_INDEX]) << 8) | // 取出第8-15位
            static_cast<uint32_t>(cipherHeader[KEYID_INDEX + 1]);     // 取出第0-7位

    return CheckEncryptAndDecryptParams(domainId, symAlg);
}

std::vector<unsigned char> Bas64DecodeCipherText(std::string_view ciphertext)
{
    if (ciphertext.empty() || ciphertext.size() >= CIPHERTEXT_MAX_LENGTH) {
        CCSEC_LOG_ERROR("KeyManager::Decrypt|END|returnF||Invalid param ciphertext length");
        return {};
    }

    // Step 0: decode base64 ciphertext
    auto ciphertextNative = Base64Decode(ciphertext);
    if (ciphertextNative.empty()) {
        CCSEC_LOG_ERROR("|KeyManager::Decrypt|END|returnF||Base64 decode error from ciphertext");
        return {};
    }
    return ciphertextNative;
}

std::pair<KeyManagerRC, std::vector<std::byte>> OpenbaoKeyManager::Decrypt(const CryptoSymAlg &symAlg,
                                                                           uint32_t domainId,
                                                                           std::string_view ciphertext)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto err = CheckEncryptAndDecryptParams(domainId, symAlg);
    if (err != KeyManagerRC::OK) {
        return {err, {}};
    }

    auto ciphertextNative = Bas64DecodeCipherText(ciphertext);
    if (ciphertextNative.empty()) {
        return {KeyManagerRC::INVALID_PARAM, {}};
    }

    CryptoSymAlg headerSymAlg;
    uint32_t headerDomainId = 0;
    uint32_t headerKeyId = 0;
    auto ret = ParseCipherHeader(ciphertextNative, headerSymAlg, headerDomainId, headerKeyId);
    if (ret != KeyManagerRC::OK) {
        return {ret, {}};
    }

    if (headerSymAlg != symAlg) {
        CCSEC_LOG_ERROR("KeyManager::Decrypt|END|returnF|The symAlg "
                        << static_cast<int>(symAlg) << " of the parameter is inconsistent with the symAlg "
                        << static_cast<int>(headerSymAlg) << " of the ciphertext parsing section");
        return {KeyManagerRC::INVALID_PARAM, {}};
    }

    if (headerDomainId != domainId) {
        CCSEC_LOG_ERROR("KeyManager::Decrypt|END|returnF|The domainId " << domainId
                                                                        << " of the parameter is "
                                                                           "inconsistent with the domainId "
                                                                        << headerDomainId
                                                                        << " of "
                                                                           "the ciphertext parsing section");
        return {KeyManagerRC::INVALID_PARAM, {}};
    }

    auto domainIt = domainKeyMap_.find(domainId);
    auto subMap = domainIt->second;
    if (subMap.find(headerKeyId) == subMap.end()) {
        CCSEC_LOG_ERROR("KeyManager::Decrypt|END|returnF|The keyId in the ciphertext does not exist in the domainId "
                        << domainId << ".");
        return {KeyManagerRC::ERROR, {}};
    }

    // 创建一个新的 vector，包含偏移后的数据
    std::vector<unsigned char> offsetData(ciphertextNative.begin() + MAX_INDEX, ciphertextNative.end());
    // 进行解密
    auto vec = VaultDecrypt(headerSymAlg, headerDomainId, headerKeyId, MakeStringView(offsetData));
    if (vec.empty()) {
        CCSEC_LOG_ERROR("KeyManager::Decrypt|END|returnF|decrypt error.");
        return {KeyManagerRC::ERROR, {}};
    }
    CCSEC_LOG_INFO("KeyManager::Decrypt|END|returnS|decrypt success.");
    return {KeyManagerRC::OK, vec};
}
} // namespace cdf
