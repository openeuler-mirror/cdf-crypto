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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cdf/modules/authentication/kerberos/define.h"

namespace cdf {

class KrbClient {
public:
    KrbClient();
    ~KrbClient();

    KrbResult ClientInit(const std::string &inClientName, const std::string &inServiceName,
                         const std::string &keyTable);

    bool InitParam();

    std::pair<KrbResult, std::vector<uint8_t>> ClientGetCred([[maybe_unused]] int flags);

    // NOTE the defailed info of cred (credential) gets changed during auth server process
    KrbResult ClientAuthServer([[maybe_unused]] int flags, char *cred, uint32_t credLen);

    static std::shared_ptr<KrbClient> GetAuthentication(const std::string &name);

private:
    // pimpl design pattern
    class Impl; // forward declaration
    std::unique_ptr<Impl> impl_;
    constexpr static const std::string_view KERBEROS = "kerberos";
};
} // namespace cdf
