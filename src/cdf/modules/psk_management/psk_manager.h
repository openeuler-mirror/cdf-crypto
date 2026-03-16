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

#pragma once

#include <atomic>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <string>
#include <string_view>

#include "cdf/modules/psk_management/psk.h"
#include "cdf/modules/psk_management/psk_callback_mgr.h"
#include "cdf/modules/psk_management/psk_define.h"

namespace cdf {

class PskManager {
public:
    ~PskManager() = default;
    PskManager(const PskManager &) = delete;
    void operator=(const PskManager &) = delete;

    // 获取实例的静态方法
    static PskManager &GetInstance();
    // 初始化函数
    PskManagerRC Init(const PsKManagerInitOptions &opt);

    PskManagerRC UnInit();

    PskManagerRC GeneratePsk(const PskParam &pskParam, Psk &psk);

    PskManagerRC ImportPsk(const PskParam &pskParam, const std::vector<uint8_t> &pskContent, Psk &psk);

    PskManagerRC UpdatePsk(const uint32_t pskId, const std::vector<uint8_t> pskContent, Psk &psk);

    PskManagerRC DeletePsk(const uint32_t pskId);

    PskManagerRC GetPsk(const uint32_t pskId, std::vector<uint8_t> &pskContent);

    PskManagerRC GetPskMetaData(const uint32_t pskId, PskMetaData &pskMetaData);

    PskManagerRC CheckPskValid(const uint32_t pskId);

    PskManagerRC CheckPskValidAndAutoUpdate(const uint32_t pskId);

    PskManagerRC LoadAllPsk(const std::vector<std::string> &pskList);

private:
    PskManager() = default;

    std::shared_mutex rwMutex_;                              // 共享锁
    PsKManagerInitOptions options_{};                        // pskManager配置
    static std::atomic<int> initCount_;                      // 初始化次数
    std::map<std::vector<uint8_t>, uint32_t> pskContentMap_; // PSK凭证map, key：pskContent value:psk object
    std::map<uint32_t, Psk> pskIdMap_;                       // PSK凭证map, key：pskId value:psk object
    std::atomic<uint32_t> curPskMaxId_{1};                   // 当前PSK ID

    bool CheckInited() const
    {
        return initCount_.load() > 0;
    }
    PskManagerRC ValidateInitOptions(const PsKManagerInitOptions &opt);
    PskManagerRC ValidatePskParams(const PskParam &pskParam);
    static PskManagerRC ConstructPskMetaJsonString(const Psk &psk, std::string &pskMetaJson);
    void BuildPskObj(const PskParam &pskParam, const std::vector<uint8_t> &pskContent, Psk &psk);
    static PskManagerRC GeneratePskContent(uint32_t pskLength, std::vector<uint8_t> &pskContent);
    PskManagerRC BuildAndEncryptPskToken(const Psk &psk, std::vector<std::byte> &encryptedToken);
    PskManagerRC EncryptPskToken(const std::vector<std::byte> &pskToken, std::vector<std::byte> &encryptedToken) const;
    static std::vector<std::byte> ConcatenatePskToken(const std::vector<uint8_t> &pskContent,
                                                      const std::string &pskMetaJson);
    void ClearAllData();
    PskManagerRC DecryptPskCiphertext(const std::string &pskCiphertext, std::vector<std::byte> &pskToken) const;
    PskManagerRC ParsePskMetaJsonString(const std::string &pskMetaJson, PskMetaData &pskMetaData);
    PskManagerRC DecryptAndParsePskToken(const std::string &encryptedPskToken, std::vector<uint8_t> &pskContent,
                                         PskMetaData &pskMetaData);
    PskManagerRC SplitPskToken(const std::vector<std::byte> &pskToken, std::vector<uint8_t> &pskContent,
                               std::string &pskMetaJson);
    PskManagerRC ValidatePskMetaData(const PskMetaData &pskMetaData);
    void BuildPskObjWithMetaData(const PskMetaData &pskMeta, const std::vector<uint8_t> &pskContent, Psk &psk);
    PskManagerRC TriggerCreatePskCallback(uint32_t pskId, const std::vector<std::byte> &encryptedPskToken);
    PskManagerRC TriggerUpdatePskCallback(uint32_t pskId, const std::vector<std::byte> &encryptedPskToken);
    PskManagerRC TriggerDeletePskCallback(uint32_t pskId);
};

} // namespace cdf
