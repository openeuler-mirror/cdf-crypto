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

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "cdf/modules/authentication/kerberos/krb_client.h"
#include "kerberos_stubs.h"

namespace cdf::test {
namespace {

constexpr const char *CLIENT_NAME = "user@EXAMPLE.COM";
constexpr const char *SERVICE_NAME = "server@EXAMPLE.COM";

KrbResult Initialize(KrbClient &client)
{
    return client.ClientInit(CLIENT_NAME, SERVICE_NAME, MakeMinimalKeytab().buf);
}

} // namespace

class KrbClientTest : public ::testing::Test {
protected:
    KerberosApiScope scope_;
};

TEST_F(KrbClientTest, FactoryAcceptsOnlyKerberos)
{
    EXPECT_EQ(KrbClient::GetAuthentication(""), nullptr);
    EXPECT_EQ(KrbClient::GetAuthentication("other"), nullptr);
    EXPECT_NE(KrbClient::GetAuthentication("kerberos"), nullptr);
}

TEST_F(KrbClientTest, RejectsEmptyInitializationInputs)
{
    KrbClient client;
    auto keytab = MakeMinimalKeytab().buf;

    EXPECT_EQ(client.ClientInit("", SERVICE_NAME, keytab).GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(client.ClientInit(CLIENT_NAME, "", keytab).GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(client.ClientInit(CLIENT_NAME, SERVICE_NAME, "").GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(scope_.State().initContextCalls, 0);
}

TEST_F(KrbClientTest, InitializesNamesAndCredentialsAndCleansOnDestruction)
{
    {
        KrbClient client;
        auto result = Initialize(client);
        ASSERT_EQ(result.GetKrbRc(), KrbRc::CDF_OK);
        EXPECT_EQ(result.mMessage, "ClientInit Succeed");
        EXPECT_EQ(scope_.State().importNameCalls, 2);
        EXPECT_EQ(scope_.State().acquireCredentialCalls, 1);
    }
    EXPECT_EQ(scope_.State().releaseNameCalls, 2);
    EXPECT_EQ(scope_.State().releaseCredentialCalls, 1);
    EXPECT_EQ(scope_.State().destroyCacheCalls, 1);
}

TEST_F(KrbClientTest, ReportsClientNameImportFailure)
{
    scope_.State().gssImportNameMajor = GSS_S_FAILURE;
    KrbClient client;

    auto result = Initialize(client);

    EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_ERROR);
    EXPECT_EQ(result.mMessage, "gss_import_name(inClientName) Failed");
    EXPECT_EQ(scope_.State().acquireCredentialCalls, 0);
}

TEST_F(KrbClientTest, ReleasesClientNameWhenCredentialAcquireFails)
{
    scope_.State().gssAcquireCredMajor = GSS_S_FAILURE;
    KrbClient client;

    auto result = Initialize(client);

    EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_ERROR);
    EXPECT_EQ(result.mMessage, "gss_acquire_cred Failed");
    EXPECT_EQ(scope_.State().releaseNameCalls, 1);
    EXPECT_EQ(scope_.State().importNameCalls, 1);
}

TEST_F(KrbClientTest, CleansClientResourcesWhenServiceImportFails)
{
    scope_.State().gssImportNameMajor = GSS_S_FAILURE;
    scope_.State().failImportNameOnCall = 2;
    KrbClient client;

    auto result = Initialize(client);

    EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_ERROR);
    EXPECT_EQ(result.mMessage, "gss_import_name(inServiceName) Failed");
    EXPECT_EQ(scope_.State().importNameCalls, 2);
    EXPECT_EQ(scope_.State().releaseCredentialCalls, 1);
}

TEST_F(KrbClientTest, GetCredBeforeInitReturnsErrorThroughWrapper)
{
    KrbClient client;

    auto [result, token] = client.ClientGetCred(0);

    EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_ERROR);
    EXPECT_TRUE(token.empty());
    EXPECT_EQ(scope_.State().initSecurityContextCalls, 1);
    EXPECT_EQ(scope_.State().deleteContextCalls, 1);
}

TEST_F(KrbClientTest, ReturnsExactInitialTokenForCompleteAndContinue)
{
    for (OM_uint32 status : {GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED}) {
        scope_.State().Reset();
        scope_.State().gssInitContextMajor = status;
        scope_.State().outputToken = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        KrbClient client;
        ASSERT_EQ(Initialize(client).GetKrbRc(), KrbRc::CDF_OK);

        auto [result, token] = client.ClientGetCred(0);

        EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_OK);
        EXPECT_EQ(token, (std::vector<uint8_t>{0x01, 0x02, 0x03}));
        EXPECT_EQ(scope_.State().releaseBufferCalls, 1);
    }
}

TEST_F(KrbClientTest, ReportsInitialSecurityContextFailure)
{
    KrbClient client;
    ASSERT_EQ(Initialize(client).GetKrbRc(), KrbRc::CDF_OK);
    scope_.State().gssInitContextMajor = GSS_S_FAILURE;

    auto [result, token] = client.ClientGetCred(0);

    EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_ERROR);
    EXPECT_TRUE(token.empty());
    EXPECT_EQ(scope_.State().deleteContextCalls, 0);
}

TEST_F(KrbClientTest, RejectsInvalidServerCredentials)
{
    KrbClient client;
    char credential = 'x';

    EXPECT_EQ(client.ClientAuthServer(0, nullptr, 1).GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(client.ClientAuthServer(0, &credential, 0).GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(client.ClientAuthServer(0, &credential, static_cast<uint32_t>(MAX_FILE_SIZE) + 1).GetKrbRc(),
        KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(scope_.State().initSecurityContextCalls, 0);
}

TEST_F(KrbClientTest, AuthenticatesServerAndReleasesOutputsOnce)
{
    KrbClient client;
    ASSERT_EQ(Initialize(client).GetKrbRc(), KrbRc::CDF_OK);
    scope_.State().outputToken = {std::byte{0x01}};
    char credential[] = "server-token";

    auto result = client.ClientAuthServer(0, credential, sizeof(credential) - 1);

    EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_OK);
    EXPECT_EQ(result.mMessage, "ClientAuthServer Succeed");
    EXPECT_EQ(scope_.State().releaseCredentialCalls, 1);
    EXPECT_EQ(scope_.State().releaseBufferCalls, 1);
}

TEST_F(KrbClientTest, ReportsContinueAndUnknownServerAuthResults)
{
    for (OM_uint32 status : std::array<OM_uint32, 2>{GSS_S_CONTINUE_NEEDED, GSS_S_FAILURE}) {
        scope_.State().Reset();
        scope_.State().gssInitContextMajor = status;
        KrbClient client;
        ASSERT_EQ(Initialize(client).GetKrbRc(), KrbRc::CDF_OK);
        char credential[] = "server-token";

        auto result = client.ClientAuthServer(0, credential, sizeof(credential) - 1);

        EXPECT_EQ(result.GetKrbRc(), KrbRc::CDF_ERROR);
        EXPECT_EQ(scope_.State().releaseCredentialCalls, 1);
        EXPECT_EQ(scope_.State().releaseBufferCalls, 1);
        if (status == GSS_S_FAILURE) {
            EXPECT_EQ(scope_.State().deleteContextCalls, 0);
        }
    }
}

} // namespace cdf::test
