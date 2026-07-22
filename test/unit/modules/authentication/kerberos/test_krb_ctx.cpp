/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
          * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <cstring>
#include <string>

#include "gtest/gtest.h"
#include "krb5/krb5.h"
#include "securec.h"

#include "cdf/modules/authentication/kerberos/krb_client.h"
#include "cdf/modules/authentication/kerberos/krb_ctx.h"
#include "cdf/modules/authentication/kerberos/krb_server.h"

namespace cdf::test {

constexpr std::string_view TEST_KEYTAB_PATH = "/root/example.keytab";
constexpr std::string_view TEST_SERVER_PRINCIPAL = "server@EXAMPLE.COM";
constexpr std::string_view TEST_CLIENT_PRINCIPAL = "user@EXAMPLE.COM";

// -------------------------------------
// Tutorial of kerberos test
// -------------------------------------
//
// STEP 1: Configure /etc/krb5.conf
//
//     [libdefaults]
//     default_realm = EXAMPLE.COM
//     kdc_timesync = 1
//     ccache_type = 4
//     forwardable = true
//     proxiable = true
//
//     [realms]
//     EXAMPLE.COM = {
//     kdc = localhost
//     admin_server = localhost
//     }
//
//     [domain_realm]
//     .example.com = EXAMPLE.COM
//     example.com = EXAMPLE.COM
//
// STEP 2: Create Kerberos Database
//
//     sudo krb5_newrealm
//     (enter password for master)
//
// STEP 3: Create Test User
//
//     sudo kadmin.local
//     addprinc user@EXAMPLE.COM
//     addprinc server@EXAMPLE.COM
//     (enter password for user and server)
//
// STEP 4: Create Keytable
//
//     ktutil
//     add_entry -password -p user@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
//     (enter password for user)
//     add_entry -password -p server@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
//     (enter password for server)
//     wkt example.keytab
//     exit
class TestCDFAuthenticationKrb : public testing ::Test {};

TEST_F(TestCDFAuthenticationKrb, DISABLED_KrbServer_ShouldWork)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK); // expect succees

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_OK); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_OK); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    ret = client.ClientAuthServer(0, serverCredOut, serverCredLenOut);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_OK); // expect succees
}

TEST_F(TestCDFAuthenticationKrb, DISABLED_KrbServer_ShouldNotWork)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK); // expect succees

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_OK); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK); // expect fail

    serverInCred[0]--;

    serverCredOut[0]++;

    // Server auth client using client's credential, and get a resulting credential
    ret = client.ClientAuthServer(0, serverCredOut, serverCredLenOut);
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_ERROR); // expect fail
}

TEST_F(TestCDFAuthenticationKrb, DISABLED_KrbServer_ShouldNotWork1)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);

    auto ret = server.ServerInit(serverPrincipalName, "123231");
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_ERROR); // expect fail

    ret = server.ServerInit(serverPrincipalName, "");
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_INVALID_PARAM); // expect fail

    ret = server.ServerInit("", {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_INVALID_PARAM); // expect fail

    // client
    KrbClient client;

    ret = client.ClientInit("12321", serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_ERROR); // expect fail

    ret = client.ClientInit(clientPrincipalName, "123231", {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK);

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, "");
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_INVALID_PARAM); // expect fail

    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, "123231");
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_ERROR); // expect fail
}

// 验证密钥在传输过程中被篡改、Clinet与Server认证失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_002)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // client
    KrbClient client;

    // 初始化client
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ(ret1.mResult, static_cast<uint32_t>(0)); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect fail

    // 篡改凭证
    serverInCred[0]--;
    serverCredOut[0]++;

    // 认证失败
    ret = client.ClientAuthServer(0, serverCredOut, serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect fail
}

// 验证调用ClientInit接口，inClientName参数非法，初始化失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_003)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;
    // 获取keytable
    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    // client
    KrbClient client;
    // 初始化client未注册的客户端
    auto ret = client.ClientInit("user1@EXAMPLE.COM", serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect fail 1
    // 初始化client客户端为空
    ret = client.ClientInit("", serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(2)); // expect fail 2
    // 初始化client客户端为错误格式
    ret = client.ClientInit("user1", serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect fail 1
}

// 验证调用ClientInit接口，inKeytab参数非法，初始化失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_005)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;
    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);

    KrbClient client;
    // 初始化client keytable为空及其长度
    auto ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {"", keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect fail 1
    // 初始化client被篡改的keytable及其长度
    keytable[6]++; // 6
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect fail 1
}

// 验证调用ClientAuthServer接口，凭证为空，鉴权失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_007)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ(ret1.mResult, static_cast<uint32_t>(0)); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // 凭证为空，认证失败
    char *ptr = nullptr;
    // Server auth client using client's credential, and get a resulting credential
    ret = client.ClientAuthServer(0, ptr, serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(2)); // expect succees 2
}

// 验证调用ClientAuthServer接口，凭证被篡改，鉴权失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_008)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ(ret1.mResult, static_cast<uint32_t>(0)); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // 篡改凭证，认证失败
    serverCredOut[0]++;
    // Server auth client using client's credential, and get a resulting credential
    ret = client.ClientAuthServer(0, serverCredOut, serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees
}

// 验证调用ClientAuthServer接口，凭证长度非法，鉴权失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_009)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ(ret1.mResult, static_cast<uint32_t>(0)); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // 凭证长度非法，认证失败
    ret = client.ClientAuthServer(0, serverCredOut, 1);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees
}

// 验证调用ClientAuthServer接口，凭证长度与凭证不一致，鉴权失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_010)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ(ret1.mResult, static_cast<uint32_t>(0)); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    // 凭证长度credLenOut-1,认证失败
    ret = client.ClientAuthServer(0, serverCredOut, serverCredLenOut - 1);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees
}

// 验证调用ServerInit接口，inKeytab参数非法，初始化失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_011)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {"", keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees 1
    keytable[6]++; // 6
    ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees 2
}

// 验证调用ServerInit接口，inKeytabLen参数非法，初始化失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_012)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {
                                                          keytable,
                                                      });
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1));
}

// 验证调用ServerInit接口，servicePrincipleName参数非法，初始化失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_013)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    // 服务端名为空
    auto ret = server.ServerInit("", {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(2)); // expect succees 2
    // 服务端名未注册
    ret = server.ServerInit("server1@EXAMPLE.COM", {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees
    // 服务端名格式错误
    ret = server.ServerInit("server1", {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees
}

// 验证调用ServerAuth接口，cred参数非法，初始化失败
TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_014)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees 0

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees 0

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ(ret1.mResult, static_cast<uint32_t>(0)); // expect succees 0

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret = server.ServerAuth(0, "", &serverCredOut, &serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(2)); // 2

    serverInCred[0]++;
    ret = server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect succees 1
}

TEST_F(TestCDFAuthenticationKrb, Authentication_Kerberos_016)
{
    // server
    auto client = KrbClient::GetAuthentication("");
    EXPECT_EQ(client, nullptr);
    client = KrbClient::GetAuthentication("gfhewfe");
    EXPECT_EQ(client, nullptr);
}

TEST_F(TestCDFAuthenticationKrb, Authentication_Kerberos_017)
{
    // server
    auto server = KrbServer::GetAuthentication("");
    EXPECT_EQ(server, nullptr);
    server = KrbServer::GetAuthentication("gfhewfe");
    EXPECT_EQ(server, nullptr);
}

TEST_F(TestCDFAuthenticationKrb, DISABLED_Authentication_Kerberos_018)
{
    // GIVEN
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    bool enableEncryption = false;

    // client
    auto client = KrbClient::GetAuthentication("kerberos");

    char *keytable;
    uint32_t keytableLen = 0;
    {
        KrbServer server;
        server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    }

    auto ret = client->ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect succees

    ret = client->ClientInit("@dsa@dsae0@dsa", serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect failure

    ret = client->ClientInit(clientPrincipalName, "@dsa@dsae0@dsa", {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect failure: you cannot have multiple @

    ret = client->ClientInit(clientPrincipalName, "dsae0@dsa", {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect okay

    ret = client->ClientInit(clientPrincipalName, "dsae0", {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(0)); // expect okay, using default realm

    ret = client->ClientInit(clientPrincipalName, "dsae0@dsa/", {keytable, keytableLen});
    EXPECT_EQ(ret.mResult, static_cast<uint32_t>(1)); // expect failure: you cannot have / in realm
}

TEST_F(TestCDFAuthenticationKrb, DISABLED_GetKerberosKeytab_KeytabIsNull)
{
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    bool enableEncryption = false;

    // server
    KrbServer server;
    auto ret =
        server.GetKerberosKeytab(keyTabFilePath, &keytable, nullptr, enableEncryption);
    EXPECT_FALSE(ret);
    ret = server.GetKerberosKeytab(keyTabFilePath, nullptr, &keytableLen, enableEncryption);
    EXPECT_FALSE(ret);
    ret = server.GetKerberosKeytab(keyTabFilePath, nullptr, nullptr, enableEncryption);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFAuthenticationKrb, DISABLED_ServerAuth_ServerCredOutIsNull)
{
    // placeholder
    char *keytable;
    uint32_t keytableLen = 0;

    // init params
    const std::string keyTabFilePath = std::string(TEST_KEYTAB_PATH);
    const std::string serverPrincipalName = std::string(TEST_SERVER_PRINCIPAL);
    const std::string clientPrincipalName = std::string(TEST_CLIENT_PRINCIPAL);
    bool enableEncryption = false;

    // server
    KrbServer server;

    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    auto ret = server.ServerInit(serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK); // expect succees

    // client
    KrbClient client;

    // NOTE now we have unknown realm error: KRB5_REALM_UNKNOWN
    ret = client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});
    EXPECT_EQ((KrbRc)ret.mResult, KrbRc::CDF_OK); // expect succees

    // Client get credential
    auto [ret1, cred] = client.ClientGetCred(0);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_OK); // expect succees

    // Server auth client using client's credential, and get a resulting credential
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy_s(serverInCred.data(), serverInCred.size(), cred.data(), cred.size());

    char *serverCredOut;
    uint32_t serverCredLenOut;
    ret1 = server.ServerAuth(0, serverInCred, nullptr, &serverCredLenOut);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_ERROR);

    ret1 = server.ServerAuth(0, serverInCred, &serverCredOut, nullptr);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_ERROR);

    ret1 = server.ServerAuth(0, serverInCred, nullptr, nullptr);
    EXPECT_EQ((KrbRc)ret1.mResult, KrbRc::CDF_ERROR);
}

// Stub tests for KrbCtx - testing logic without real Kerberos environment
class TestKrbCtxStub : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(TestKrbCtxStub, KrbCtx_KerberosInitKeytab_EmptyKeytab)
{
    // Test with empty keytab value
    KrbCtx ctx;
    KeytabValue emptyKeytab;
    emptyKeytab.buf = "";

    auto result = ctx.KerberosInitKeytab(emptyKeytab, "test@EXAMPLE.COM");
    // Should fail because krb5_init_context will fail without krb5 library
    EXPECT_NE(result.mResult, 0);
}

TEST_F(TestKrbCtxStub, KrbCtx_KerberosInitCCache_EmptyKeytab)
{
    // Test with empty keytab value for CCache
    KrbCtx ctx;
    KeytabValue emptyKeytab;
    emptyKeytab.buf = "";

    auto result = ctx.KerberosInitCCache(emptyKeytab, "test@EXAMPLE.COM");
    // Should fail because krb5_init_context will fail without krb5 library
    EXPECT_NE(result.mResult, 0);
}

} // namespace cdf::test
