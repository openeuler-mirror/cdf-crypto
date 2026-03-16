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

#include "cdf/cli/cmd.h"

#include <iostream>
#include <memory>
#include <string>

#include "cdf/base/ccsec_logger.h"
#include "cdf/cli/defines.h"
#include "cdf/cli/kmc_cmd.h"

namespace cdf {

#define EMPLACE_COMMAND(cmd, handler)                                                          \
    do {                                                                                       \
        auto tmp##handler = std::make_shared<handler>();                                       \
        if (tmp##handler == nullptr) {                                                         \
            CCSEC_LOG_ERROR("|create handler|END|returnF||Failed to create " << #handler << " cmd"); \
            return CryptionToolRc::INTERNAL_ERROR;                                             \
        }                                                                                      \
        handlers.emplace(cmd, tmp##handler);                                                   \
    } while (0)

CryptionToolRc CmdManager::Initialize()
{
    EMPLACE_COMMAND("--removekey", RemovekeyCmd);
    EMPLACE_COMMAND("--displaykey", DisplaykeyCmd);
    EMPLACE_COMMAND("--createkey", CreateKeyCmd);
    EMPLACE_COMMAND("--encrypt", EncryptKeyCmd);
    EMPLACE_COMMAND("--reEncrypt", ReEncryptCmd);

    return CryptionToolRc::OK;
}

std::shared_ptr<Cmd> CmdManager::GetHandler(const std::string &cmd)
{
    auto it = handlers.find(cmd);
    if (it == handlers.end()) {
        return nullptr;
    }
    return it->second;
}

} // namespace cdf
