// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
// Confidential Data defensive Framework is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//           http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#include "cdf/modules/key_management/vault/vault_key_manager.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "cdf/base/ccsec_logger.h"
#include "cdf/modules/cryption/native_cryptor.h"
#include "cdf/modules/key_management/openbao/openbao_utils.h"
#include "cdf/utils/base64.h"

#ifdef __cplusplus
extern "C" {
cdf::VaultKeyManager *BorrowVaultKeyManager()
{
    auto &singleton = cdf::VaultKeyManager::GetInstance();
    return &singleton;
}
}
#endif

namespace cdf {
KeyManagerRC VaultKeyManager::UnInit()
{
    auto ret = openbaoKeyManager.UnInit();
    openbaoKeyManager.SetType(KeyManagerTy::OPENBAO);
    return ret;
}

KeyManagerRC VaultKeyManager::Init(std::string_view exePath, std::string_view accessToken, uint32_t domainCount)
{
    openbaoKeyManager.SetType(KeyManagerTy::VAULT);
    return openbaoKeyManager.Init(exePath, accessToken, domainCount);
}

std::pair<KeyManagerRC, uint32_t> VaultKeyManager::CreateKey(uint32_t domainId)
{
    return openbaoKeyManager.CreateKey(domainId);
}

KeyManagerRC VaultKeyManager::DisplayKey(uint32_t domainId) const
{
    return openbaoKeyManager.DisplayKey(domainId);
}

KeyManagerRC VaultKeyManager::DisplayAllKey() const
{
    return openbaoKeyManager.DisplayAllKey();
}

KeyManagerRC VaultKeyManager::RemoveKey(uint32_t domainId, uint32_t keyId)
{
    return openbaoKeyManager.RemoveKey(domainId, keyId);
}

std::vector<std::byte> VaultKeyManager::GetLatestKey(uint32_t domainId, uint32_t &keyId)
{
    return openbaoKeyManager.GetLatestKey(domainId, keyId);
}

KeyManagerRC VaultKeyManager::DeleteAllKey() const
{
    return openbaoKeyManager.DeleteAllKey();
}

KeyManagerRC VaultKeyManager::CheckDomainKeysExpired(uint32_t domainId, uint32_t lead)
{
    return openbaoKeyManager.CheckDomainKeysExpired(domainId, lead);
}

KeyManagerRC VaultKeyManager::CheckDomainKeysExpiredAndAutoUpdate(uint32_t domainId, uint32_t lead)
{
    return openbaoKeyManager.CheckDomainKeysExpiredAndAutoUpdate(domainId, lead);
}

std::pair<KeyManagerRC, std::vector<std::byte>> VaultKeyManager::Encrypt(const CryptoSymAlg &symAlg, uint32_t domainId,
                                                                         std::string_view plaintext)
{
    return openbaoKeyManager.Encrypt(symAlg, domainId, plaintext);
}

std::pair<KeyManagerRC, std::vector<std::byte>> VaultKeyManager::Decrypt(const CryptoSymAlg &symAlg, uint32_t domainId,
                                                                         std::string_view ciphertext)
{
    return openbaoKeyManager.Decrypt(symAlg, domainId, ciphertext);
}
} // namespace cdf
