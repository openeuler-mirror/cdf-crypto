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

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>

#include "gtest/gtest.h"

#include "cdf/modules/authentication/kerberos/krb_server.h"
#include "kerberos_stubs.h"
#include "temp_directory.h"

namespace cdf::test {
namespace {
constexpr const char *SERVICE = "server@EXAMPLE.COM";

KrbResult Init(KrbServer &server)
{
    return server.ServerInit(SERVICE, MakeMinimalKeytab().buf);
}
}

class KrbServerTest : public ::testing::Test {
protected:
    KerberosApiScope scope_;
};

TEST_F(KrbServerTest, FactoryAndInputValidation)
{
    EXPECT_EQ(KrbServer::GetAuthentication(""), nullptr);
    EXPECT_NE(KrbServer::GetAuthentication("kerberos"), nullptr);
    KrbServer server;
    EXPECT_EQ(server.ServerInit("", "x").GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(server.ServerInit(SERVICE, "").GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
}

TEST_F(KrbServerTest, ReadsPlainKeytabAndChecksFiles)
{
    TempDirectory temp;
    auto file = temp.Path() / "keytab";
    { std::ofstream out(file, std::ios::binary); out << "abc"; }
    KrbServer server;
    EXPECT_TRUE(server.CheckFile(file));
    char *buffer = nullptr;
    uint32_t length = 0;
    ASSERT_TRUE(server.GetKerberosKeytab(file, &buffer, &length, false));
    ASSERT_EQ(length, 3U);
    EXPECT_EQ(std::string(buffer, length), "abc");
    free(buffer);
    EXPECT_FALSE(server.CheckFile(temp.Path() / "missing"));
    EXPECT_FALSE(server.GetKerberosKeytab(temp.Path() / "missing", &buffer, &length, false));
    EXPECT_FALSE(server.GetKerberosKeytab(file, nullptr, &length, false));
    EXPECT_FALSE(server.GetKerberosKeytab(file, &buffer, nullptr, false));
}

TEST_F(KrbServerTest, RejectsEmptyAndDirectoryKeytabs)
{
    TempDirectory temp;
    auto empty = temp.Path() / "empty";
    std::ofstream(empty).close();
    KrbServer server;
    char *buffer = nullptr;
    uint32_t length = 0;
    EXPECT_FALSE(server.CheckFile(empty));
    EXPECT_FALSE(server.GetKerberosKeytab(empty, &buffer, &length, false));
    EXPECT_FALSE(server.CheckFile(temp.Path()));
    EXPECT_FALSE(server.GetKerberosKeytab(temp.Path(), &buffer, &length, false));
    EXPECT_FALSE(server.GetKerberosKeytab(std::string(PATH_MAX + 1, 'x'), &buffer, &length, false));
}

TEST_F(KrbServerTest, InitializesAndCleansGssResources)
{
    {
        KrbServer server;
        ASSERT_EQ(Init(server).GetKrbRc(), KrbRc::CDF_OK);
        EXPECT_EQ(scope_.State().importNameCalls, 1);
        EXPECT_EQ(scope_.State().acquireCredentialCalls, 1);
    }
    EXPECT_EQ(scope_.State().releaseNameCalls, 1);
    EXPECT_EQ(scope_.State().releaseCredentialCalls, 1);
}

TEST_F(KrbServerTest, ReportsInitializationFailures)
{
    KrbServer server;
    EXPECT_EQ(server.ServerInit(SERVICE, "bad").GetKrbRc(), KrbRc::CDF_ERROR);
    scope_.State().gssImportNameMajor = GSS_S_FAILURE;
    EXPECT_EQ(Init(server).mMessage, "gss_import_name Failed");
    scope_.State().Reset();
    scope_.State().gssAcquireCredMajor = GSS_S_FAILURE;
    EXPECT_EQ(Init(server).mMessage, "ServerInit gss_acquire_cred error");
}

TEST_F(KrbServerTest, AuthValidatesArgumentsAndStatus)
{
    KrbServer server;
    ASSERT_TRUE(Init(server).OK());
    char *output = reinterpret_cast<char *>(0x1234);
    uint32_t length = 77;
    EXPECT_EQ(server.ServerAuth(0, "", &output, &length).GetKrbRc(), KrbRc::CDF_INVALID_PARAM);
    EXPECT_EQ(server.ServerAuth(0, "cred", nullptr, &length).GetKrbRc(), KrbRc::CDF_ERROR);
    EXPECT_EQ(server.ServerAuth(0, "cred", &output, nullptr).GetKrbRc(), KrbRc::CDF_ERROR);
    EXPECT_EQ(output, reinterpret_cast<char *>(0x1234));
    EXPECT_EQ(length, 77U);
    scope_.State().outputToken = {std::byte{0x01}, std::byte{0x02}};
    auto result = server.ServerAuth(0, "cred", &output, &length);
    EXPECT_TRUE(result.OK());
    EXPECT_EQ(length, 2U);
    EXPECT_EQ(scope_.State().deleteContextCalls, 1);
    EXPECT_EQ(scope_.State().inquireContextCalls, 1);
    EXPECT_EQ(scope_.State().displayNameCalls, 1);
}

TEST_F(KrbServerTest, HandlesAcceptAndPrincipalFailures)
{
    KrbServer server;
    ASSERT_TRUE(Init(server).OK());
    char *output = nullptr;
    uint32_t length = 0;
    scope_.State().outputToken = {std::byte{0x01}};
    scope_.State().gssAcceptContextMajor = GSS_S_CONTINUE_NEEDED;
    EXPECT_FALSE(server.ServerAuth(0, "cred", &output, &length).OK());
    scope_.State().Reset();
    scope_.State().outputToken = {std::byte{0x01}};
    scope_.State().gssInquireContextMajor = GSS_S_FAILURE;
    EXPECT_FALSE(server.ServerAuth(0, "cred", &output, &length).OK());
}
} // namespace cdf::test
