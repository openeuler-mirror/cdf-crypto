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

#include <map>
#include <string>
#include <utility>
#include <vector>
#include <shared_mutex>
#include "cdf/modules/key_management/key_manager.h"

namespace cdf {
class OpenbaoKeyManager : public KeyManager {
public:
    ~OpenbaoKeyManager() override = default;

    OpenbaoKeyManager(const OpenbaoKeyManager &) = delete;
    void operator=(const OpenbaoKeyManager &) = delete;

    KeyManagerRC Init(std::string_view exePath, std::string_view accessToken, uint32_t domainCount) override;
    KeyManagerRC UnInit() override;

    KeyManagerTy Type() const override
    {
        return type_;
    }

    uint32_t DomainCount() const override
    {
        return domainCount_;
    }

    bool CheckInited() const override
    {
        return inited_;
    }

    // Set type
    void SetType(KeyManagerTy type)
    {
        type_ = type;
    }

    std::pair<KeyManagerRC, uint32_t> CreateKey(uint32_t domainId) override;
    KeyManagerRC RemoveKey(uint32_t domainId, uint32_t keyId) override;
    KeyManagerRC DisplayAllKey() const override;
    KeyManagerRC DisplayKey(uint32_t domainId) const override;
    KeyManagerRC DeleteAllKey();
    KeyManagerRC CheckDomainKeysExpired(uint32_t domainId, uint32_t lead) override;
    KeyManagerRC CheckDomainKeysExpiredAndAutoUpdate([[maybe_unused]] uint32_t domainId,
                                                     [[maybe_unused]] uint32_t lead) override;

    std::pair<KeyManagerRC, std::vector<std::byte>> Encrypt(const CryptoSymAlg &symAlg, uint32_t domainId,
                                                            std::string_view plaintext);
    std::pair<KeyManagerRC, std::vector<std::byte>> Decrypt(const CryptoSymAlg &symAlg, uint32_t domainId,
                                                            std::string_view ciphertext);

    std::pair<KeyManagerRC, std::vector<std::byte>> Encrypt(uint32_t domainId, std::string_view plaintext)
    {
        return Encrypt(CryptoSymAlg::AES256_GCM, domainId, plaintext);
    }

    std::pair<KeyManagerRC, std::vector<std::byte>> Decrypt(uint32_t domainId, std::string_view ciphertext)
    {
        return Decrypt(CryptoSymAlg::AES256_GCM, domainId, ciphertext);
    }

    std::vector<std::byte> GetLatestKey(uint32_t domainId, uint32_t &keyId);

    // Get an instance of key manager.
    static OpenbaoKeyManager &GetInstance()
    {
        static OpenbaoKeyManager km;
        return km;
    }

    // Borrow an instance of key manager.
    static OpenbaoKeyManager *BorrowInstance()
    {
        auto &km = GetInstance();
        return &km;
    }

private:
    bool inited_ = false;                                          // whether key manager has been inited
    uint32_t domainCount_ = 2;                                     // domain count
    std::map<uint32_t, std::map<uint32_t, int64_t>> domainKeyMap_; // domainId, <key id, key create time>

    OpenbaoKeyManager() = default;              // default constructor
    std::vector<uint8_t> accessToken_ = {};     // external access token, its okay to be empty
    std::string exePath_ = {};                  // the executable path of openbao binary
    KeyManagerTy type_ = KeyManagerTy::OPENBAO; // openbao or vault

    // read the map from existing openbao database
    KeyManagerRC PrepareMap();
    mutable std::shared_mutex mutex_;
    KeyManagerRC CheckDomainKeysExpiredParams(uint32_t domainId, uint32_t lead);
    KeyManagerRC CheckEncryptAndDecryptParams(uint32_t domainId, const CryptoSymAlg &symAlg);
    std::vector<std::byte> VaultDecrypt(const CryptoSymAlg &symAlg, uint32_t domainId, uint32_t keyId,
                                        std::string_view ciphertext);

    KeyManagerRC ParseCipherHeader(std::vector<unsigned char> cipherHeader, CryptoSymAlg &symAlg, uint32_t &domainId,
                                   uint32_t &keyId);
    KeyManagerRC HandleCommand(uint32_t domainId, uint32_t keyId);
    std::pair<KeyManagerRC, uint32_t> GenerateKeyId(uint32_t domainId);
    KeyManagerRC ValidateDomain(const uint32_t domainId) const;
};
} // namespace cdf
