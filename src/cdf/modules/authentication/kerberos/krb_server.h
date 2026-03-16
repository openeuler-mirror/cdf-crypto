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

#include "cdf/modules/authentication/kerberos/define.h"

namespace cdf {

class KrbServer {
public:
    KrbServer();
    ~KrbServer();

    // Initialize server
    KrbResult ServerInit(const std::string &servicePrincipleName, const std::string &keyTable);

    // Using server to auth a client
    KrbResult ServerAuth(int flags, const std::string &credIn, char **credOut, uint32_t *credLenOut);

    // Reset internal stored key table
    bool ResetInternalKeyTable();

    // check whether the configuration file exists
    bool CheckFile(const std::string &configPath);

    // get kerberos key tab from path
    bool GetKerberosKeytab(const std::string &path, char **outKeyTab, uint32_t *length, bool keyTabEncrypted);

    static std::shared_ptr<KrbServer> GetAuthentication([[maybe_unused]] const std::string &name);

private:
    class Impl; // forward declarations
    std::unique_ptr<Impl> impl_;
    constexpr static const std::string_view KERBEROS = "kerberos";
};
} // namespace cdf
  // pimpl design pattern
