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

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/key_manager.h"

namespace cdf {

class KmCryptor {
public:
    KmCryptor() = delete;
    explicit KmCryptor(KeyManager *km);
    explicit KmCryptor(KeyManagerTy type);

    /**
     * @brief Encrypt plaintext to base64 ciphertext with given symmetric
     * algorithm.
     * @param[in] alg
     * @param[in] plaintext
     * @param[in] domainId
     * @return std::pair<CryptionRC, std::string> {CryptionRC::OK, ciphertext}
     * on success, {CryptionRC::[OTHER_ERROR_CODE], ""} on failure.
     */
    std::pair<CryptionRC, std::vector<std::byte>> Encrypt(CryptoSymAlg alg, std::string_view plaintext,
                                                          uint32_t domainId);

    /**
     * @brief Decrypt base64 ciphertext to plaintext with given symmetric
     * algorithm.
     * @param[in] alg
     * @param[in] plaintext
     * @param[in] domainId
     * @return std::pair<CryptionRC, std::vector<uint8_t>> {CryptionRC::OK,
     * ciphertext} on success, {CryptionRC::[OTHER_ERROR_CODE], empty} on
     * failure.
     */
    std::pair<CryptionRC, std::vector<std::byte>> Decrypt(CryptoSymAlg alg, std::string_view ciphertext,
                                                          uint32_t domainId);

    std::pair<CryptionRC, std::vector<std::byte>> Encrypt(CryptoSymAlg alg, std::vector<std::byte> plaintext,
                                                          uint32_t domainId)
    {
        return Encrypt(alg, {reinterpret_cast<char *>(plaintext.data()), plaintext.size()}, domainId);
    }

    std::pair<CryptionRC, std::vector<std::byte>> Decrypt(CryptoSymAlg alg, std::vector<std::byte> ciphertext,
                                                          uint32_t domainId)
    {
        return Decrypt(alg, {reinterpret_cast<char *>(ciphertext.data()), ciphertext.size()}, domainId);
    }

protected:
    // NOTE do not free this pointer
    KeyManager *borrowed_km_;
};

} // namespace cdf
