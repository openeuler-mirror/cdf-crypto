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

constexpr std::string_view KRB5CCNAME = "MEMORY:OCKSecurityCCName";
constexpr std::string_view KRB5KTNAME = "MEMORY:OCKSecurityKTName";

struct KeytabValue {
    std::string buf;
    // char *keytabData;
    // uint32_t keytabDataLen;
};

class KrbCtx {
public:
    KrbCtx();
    ~KrbCtx();

    KrbResult KerberosInitKeytab(const KeytabValue &keytabValue, const std::string &inPrincipal,
                                 const std::string &memoryKeytabName = std::string(KRB5KTNAME));

    KrbResult KerberosInitCCache(const KeytabValue &keytabValue, const std::string &inPrincipal,
                                 const std::string &memoryKeytabName = std::string(KRB5KTNAME),
                                 const std::string &inkrb5ccname = std::string(KRB5CCNAME));

    KrbResult KerberosDestroyKeytab();

    KrbResult KerberosDestroyCCache();

    KrbResult KerberosUninit();

private:
    // pimpl design pattern
    class Impl; // forward declaration
    std::unique_ptr<Impl> impl_;
};
} // namespace cdf
