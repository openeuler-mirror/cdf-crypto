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

#ifndef CDF_TEST_KERBEROS_STUBS_H
#define CDF_TEST_KERBEROS_STUBS_H

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "cdf/connector/krb5_wrapper.h"

namespace cdf::test {

struct KerberosStubState {
    krb5_error_code initContextRc = 0;
    krb5_error_code parseNameRc = 0;
    krb5_error_code resolveKeytabRc = 0;
    krb5_error_code addKeytabEntryRc = 0;
    krb5_error_code defaultCacheRc = 0;
    krb5_error_code resolveCacheRc = 0;
    krb5_error_code allocOptionsRc = 0;
    krb5_error_code getCredentialsRc = 0;
    krb5_error_code initializeCacheRc = 0;
    krb5_error_code storeCredentialsRc = 0;
    krb5_boolean principalCompare = TRUE;

    OM_uint32 gssInquireContextMajor = GSS_S_COMPLETE;
    OM_uint32 gssDisplayNameMajor = GSS_S_COMPLETE;
    OM_uint32 gssImportNameMajor = GSS_S_COMPLETE;
    OM_uint32 gssAcquireCredMajor = GSS_S_COMPLETE;
    OM_uint32 gssInitContextMajor = GSS_S_COMPLETE;
    OM_uint32 gssAcceptContextMajor = GSS_S_COMPLETE;

    int initContextCalls = 0;
    int parseNameCalls = 0;
    int freePrincipalCalls = 0;
    int freeContextCalls = 0;
    int principalCompareCalls = 0;
    int freeKeytabEntryCalls = 0;
    int resolveKeytabCalls = 0;
    int addKeytabEntryCalls = 0;
    int closeKeytabCalls = 0;
    int removeKeytabEntryCalls = 0;
    int defaultCacheCalls = 0;
    int resolveCacheCalls = 0;
    int destroyCacheCalls = 0;
    int allocOptionsCalls = 0;
    int freeOptionsCalls = 0;
    int getCredentialsCalls = 0;
    int initializeCacheCalls = 0;
    int storeCredentialsCalls = 0;
    int freeCredentialContentsCalls = 0;
    int inquireContextCalls = 0;
    int displayNameCalls = 0;
    int releaseBufferCalls = 0;
    int acceptContextCalls = 0;
    int deleteContextCalls = 0;
    int importNameCalls = 0;
    int acquireCredentialCalls = 0;
    int initSecurityContextCalls = 0;
    int releaseNameCalls = 0;
    int releaseCredentialCalls = 0;

    std::vector<std::byte> outputToken;
    std::string displayName = "client@EXAMPLE.COM";

    void Reset();
};

class KerberosApiScope {
public:
    KerberosApiScope();
    ~KerberosApiScope();

    KerberosApiScope(const KerberosApiScope &) = delete;
    KerberosApiScope &operator=(const KerberosApiScope &) = delete;
    KerberosApiScope(KerberosApiScope &&) = delete;
    KerberosApiScope &operator=(KerberosApiScope &&) = delete;

    KerberosStubState &State();

private:
    template<typename T>
    void Replace(T &slot, T replacement)
    {
        T original = slot;
        restorers_.emplace_back([&slot, original]() { slot = original; });
        slot = replacement;
    }

    KerberosStubState state_;
    KerberosStubState *previousState_ = nullptr;
    std::vector<std::function<void()>> restorers_;
};

} // namespace cdf::test

#endif // CDF_TEST_KERBEROS_STUBS_H
