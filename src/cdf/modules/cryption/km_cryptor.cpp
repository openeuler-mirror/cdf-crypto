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

#include "cdf/modules/cryption/km_cryptor.h"

#include <dlfcn.h>

#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"
#include "cdf/base/custom_logger.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/key_manager.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/key_management/openbao/openbao_key_manager.h"
#include "cdf/modules/key_management/vault/vault_key_manager.h"

namespace cdf {

namespace {

inline CryptionRC ParseKeyManagerRC(KeyManagerRC rc)
{
    switch (rc) {
        case KeyManagerRC::OK:
            return CryptionRC::OK;
        case KeyManagerRC::INVALID_PARAM:
            return CryptionRC::INVALID_PARAM;
        case KeyManagerRC::UNINITED:
            return CryptionRC::UNINITED;
        default:
            return CryptionRC::ERROR;
    }
}

const std::vector<std::byte> EMPTY_PLACEHOLDER;

} // namespace

KmCryptor::KmCryptor(KeyManagerTy type) : KmCryptor(KeyManagerFactory::Borrow(type))
{}

KmCryptor::KmCryptor(KeyManager *km)
{
    borrowed_km_ = km;
    if (borrowed_km_ == nullptr) {
        CCSEC_LOG_WARN("|KmCryptor::KmCryptor|returnS|Init internal key manager failed, "
                       "recieved nullptr, nothing happens.");
    } else if (!borrowed_km_->CheckInited()) {
        CCSEC_LOG_ERROR("|KmCryptor::KmCryptor|returnS|Key manager is uninited. ");
    }
}

std::pair<CryptionRC, std::vector<std::byte>> KmCryptor::Encrypt(CryptoSymAlg alg, std::string_view plaintext,
                                                                 uint32_t domainId)
{
    if (borrowed_km_ == nullptr) {
        CCSEC_LOG_ERROR("|KmCryptor::Encrypt|returnF|Uninited Cryptor, error ");
        return {CryptionRC::ERROR, {}};
    }
    switch (borrowed_km_->Type()) {
        case KeyManagerTy::OPENBAO: {
            auto [rc, ciphertext] = static_cast<OpenbaoKeyManager *>(borrowed_km_)->Encrypt(alg, domainId, plaintext);
            return rc == KeyManagerRC::OK ? std::make_pair(ParseKeyManagerRC(rc), ciphertext)
                                          : std::make_pair(ParseKeyManagerRC(rc), EMPTY_PLACEHOLDER);
        }
        case KeyManagerTy::VAULT: {
            auto [rc, ciphertext] = static_cast<VaultKeyManager *>(borrowed_km_)->Encrypt(alg, domainId, plaintext);
            return rc == KeyManagerRC::OK ? std::make_pair(ParseKeyManagerRC(rc), ciphertext)
                                          : std::make_pair(ParseKeyManagerRC(rc), EMPTY_PLACEHOLDER);
        }
        default:
            return {CryptionRC::INVALID_PARAM, {}};
    }
}

std::pair<CryptionRC, std::vector<std::byte>> KmCryptor::Decrypt(CryptoSymAlg alg, std::string_view ciphertext,
                                                                 uint32_t domainId)
{
    if (borrowed_km_ == nullptr) {
        CCSEC_LOG_ERROR("|KmCryptor::Encrypt|returnF|Uninited Cryptor, error ");
        return {CryptionRC::ERROR, {}};
    }

    switch (borrowed_km_->Type()) {
        case KeyManagerTy::OPENBAO: {
            auto [rc, plaintext] = static_cast<OpenbaoKeyManager *>(borrowed_km_)->Decrypt(alg, domainId, ciphertext);
            return rc == KeyManagerRC::OK ? std::make_pair(ParseKeyManagerRC(rc), plaintext)
                                          : std::make_pair(ParseKeyManagerRC(rc), EMPTY_PLACEHOLDER);
        }
        case KeyManagerTy::VAULT: {
            auto [rc, plaintext] = static_cast<VaultKeyManager *>(borrowed_km_)->Decrypt(alg, domainId, ciphertext);
            return rc == KeyManagerRC::OK ? std::make_pair(ParseKeyManagerRC(rc), plaintext)
                                          : std::make_pair(ParseKeyManagerRC(rc), EMPTY_PLACEHOLDER);
        }
        default:
            return {CryptionRC::INVALID_PARAM, {}};
    }
}

} // namespace cdf
