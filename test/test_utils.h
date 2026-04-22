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

#include <string>
#include <vector>

#include "cdf/modules/cryption/km_cryptor.h"
#include "cdf/modules/key_management/key_manager.h"
#include "cdf/modules/key_management/key_manager_factory.h"

namespace cdf::test {

void EnsureKmUninited(KeyManager *km);

void EnsureKmUninited(KeyManagerTy type);

void SetExternalLogCallBack(int level, const char *msg);

// Common stub functions (signature-consistent across files)
std::pair<KeyManagerRC, std::string> StubRunCommandAndGetResult([[maybe_unused]] std::string_view exePath,
                                                                [[maybe_unused]] std::string_view accessToken,
                                                                [[maybe_unused]] std::string_view cmdArgs);

KeyManagerRC StubGetJsonFieldIntPairVec([[maybe_unused]] const std::string &jsonStr,
                                        [[maybe_unused]] std::vector<std::pair<uint32_t, uint32_t>> &out);

int StubGetJsonFieldMaxInt([[maybe_unused]] const std::string &jsonStr);

std::string StubGetOpenbaoLastKeyAsStr([[maybe_unused]] const std::string &readResultStr);

// Stub for OpenbaoKeyManager::Encrypt/Decrypt (uint32_t domainId, string_view plaintext)
std::pair<KeyManagerRC, std::vector<std::byte>> StubEncryptOpenbao([[maybe_unused]] const CryptoSymAlg &symAlg,
                                                                   [[maybe_unused]] uint32_t domainId,
                                                                   [[maybe_unused]] std::string_view plaintext);

std::pair<KeyManagerRC, std::vector<std::byte>> StubDecryptOpenbao([[maybe_unused]] const CryptoSymAlg &alg,
                                                                   [[maybe_unused]] uint32_t domainId,
                                                                   [[maybe_unused]] std::string_view ciphertext);

} // namespace cdf::test
