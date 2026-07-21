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

#include "cdf/modules/authentication/kerberos/krb_server.h"

#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include "gssapi/gssapi.h"
#include "krb5/krb5.h"
#include "securec.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/custom_logger.h"
#include "cdf/connector/krb5_wrapper.h"
#include "cdf/modules/authentication/kerberos/krb_ctx.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/key_management/km_cryptor.h"
#include "cdf/modules/key_management/define.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/utils/file_utils.h"

namespace cdf {

namespace {

bool g_initial = false;

inline KrbResult MakeGssOIDDescStruct(std::string_view data, gss_OID_desc_struct &gssOidInfo)
{
    const size_t maxAllowedSize = 1024 * 1024; // 1024 * 1024 = 1MB characters, it's only used for names
    if (data.size() > maxAllowedSize || data.empty()) {
        CCSEC_LOG_ERROR("|MakeGssBufferDesc|END|returnF|data size exceeds maximum allowed size");
        return {1, "data size exceeds maximum allowed size"};
    }

    gssOidInfo.length = data.size();
    gssOidInfo.elements = malloc(gssOidInfo.length);
    if (gssOidInfo.elements == nullptr) {
        std::string errMsg = "malloc failed";
        CCSEC_LOG_ERROR("|MakeGssOIDDescStruct|END|returnF|" << errMsg);
        return {1, errMsg};
    }

    // make sure data.size() is valid
    if (data.size() > gssOidInfo.length) {
        CCSEC_LOG_ERROR("|MakeGssOIDDescStruct|END|returnF|data size error");
        return {1, "data size check error"};
    }

    (void)memset_s(gssOidInfo.elements, gssOidInfo.length, 0, gssOidInfo.length);
    if (memcpy_s(gssOidInfo.elements, gssOidInfo.length, data.data(), data.size()) != EOK) {
        (void)memset_s(gssOidInfo.elements, gssOidInfo.length, 0, gssOidInfo.length);
        CCSEC_LOG_ERROR("|MakeGssOIDDescStruct|END|returnF|memcpy_s error");
        return {1, "memcpy_s error"};
    }
    return {0, "MakeGssOIDDescStruct succeed"};
}

inline KrbResult MakeGssBufferDesc(std::string_view data, gss_buffer_desc &gssBuffInfo)
{
    // validate data size
    const size_t maxAllowedSize = 1024 * 1024; // 1024 * 1024 = 1MB characters, it's only used for names
    if (data.size() > maxAllowedSize || data.empty()) {
        CCSEC_LOG_ERROR("|MakeGssBufferDesc|END|returnF|data size exceeds maximum allowed size");
        return {1, "data size exceeds maximum allowed size"};
    }

    gssBuffInfo.length = data.size();
    gssBuffInfo.value = malloc(gssBuffInfo.length);
    if (gssBuffInfo.value == nullptr) {
        std::string errMsg = "malloc failed";
        CCSEC_LOG_ERROR("|MakeGssBufferDesc|END|returnF|" << errMsg);
        return {1, errMsg};
    }

    (void)memset_s(gssBuffInfo.value, gssBuffInfo.length, 0, gssBuffInfo.length);
    if (memcpy_s(gssBuffInfo.value, gssBuffInfo.length, data.data(), data.size()) != EOK) {
        (void)memset_s(gssBuffInfo.value, gssBuffInfo.length, 0, gssBuffInfo.length);
        CCSEC_LOG_ERROR("|MakeGssBufferDesc|END|returnF|memcpy_s error");
        return {1, "memcpy_s error"};
    }
    return {0, "MakeGssBufferDesc succeed"};
}

inline uint64_t GetRandomValueInternal()
{
    std::ifstream urandom("/dev/random", std::ios::in | std::ios::binary);
    std::array<char, sizeof(uint64_t)> randomValue;
    if (urandom) {
        urandom.read(randomValue.data(), randomValue.size());
        if (urandom.fail()) {
            CCSEC_LOG_ERROR("|GetRandomValueInternal|END|returnF|Failed to read from /dev/random.");
            urandom.close();
            return 0;
        }
    } else {
        CCSEC_LOG_ERROR("|GetRandomValueInternal|END|returnF|/dev/random is not available.");
        return 0;
    }
    urandom.close();
    uint64_t ret = 0;

    if (memcpy_s(&ret, sizeof(uint64_t), randomValue.data(), randomValue.size()) != EOK) {
        CCSEC_LOG_ERROR("|GetRandomValueInternal|END|returnF|memcpy_s error");
        return 0;
    }
    return ret;
}

} // namespace

class KrbServer::Impl {
public:
    Impl() = default;
    ~Impl()
    {
        OM_uint32 minorStatus = 0;

        if (serverCredOut_ != nullptr) {
            free(serverCredOut_);
            serverCredOut_ = nullptr;
        }

        if (gssServiceName_ != nullptr) {
            Krb5Wrapper::gss_release_name(&minorStatus, &gssServiceName_);
        }

        if (serverCredentials_ != nullptr) {
            Krb5Wrapper::gss_release_cred(&minorStatus, &serverCredentials_);
        }

        if (gssServerContext_ != nullptr) {
            Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssServerContext_, nullptr);
        }

        kerberosContext_.KerberosDestroyKeytab();
    }

    bool ResetInternalKeyTable()
    {
        (void)memset_s(&keytabEntry_, sizeof(krb5_keytab_entry), 0, sizeof(krb5_keytab_entry));
        return true;
    }

    void freeGssUserNameAndServiceNameBuffer(gss_OID_desc_struct &gssUserName, gss_buffer_desc &serviceNameBuffer)
    {
        if (gssUserName.elements != nullptr) {
            free(gssUserName.elements);
            gssUserName.elements = nullptr;
        }
        if (serviceNameBuffer.value != nullptr) {
            free(serviceNameBuffer.value);
            serviceNameBuffer.value = nullptr;
        }
    }

    KrbResult ServerInit(const std::string &servicePrincipleName, const std::string &keyTable)
    {
        // Checking the validity of the arguments
        if (servicePrincipleName.empty() || keyTable.empty() || servicePrincipleName.size() > MAX_ALLOWED_NAME_LENGTH ||
            keyTable.size() > MAX_FILE_SIZE) {
            auto ret = KrbResult(KrbRc::CDF_INVALID_PARAM, "ServerInit parameter error");
            CCSEC_LOG_ERROR("|ServerInit|END|returnF|" << ret.mMessage);
            return ret;
        }

        KrbResult rtMsg(0, "ServerInit Succeed");
        // Initialize keytbale within the context
        KeytabValue keytabValue = {keyTable};
        rtMsg = kerberosContext_.KerberosInitKeytab(keytabValue, servicePrincipleName);
        if (rtMsg.mResult != 0) {
            CCSEC_LOG_ERROR("|ServerInit|END|returnF|" << rtMsg.mMessage);
            return {KrbRc::CDF_ERROR, "ServerInit keytab error"};
        }

        // Declare placeholder for krb5 error message
        OM_uint32 majorStatus;     // major error message
        OM_uint32 minorStatus = 0; // minor(detailed) error message

        // Set server to no credential
        serverCredentials_ = GSS_C_NO_CREDENTIAL;

        // Set server to no context
        gssServerContext_ = GSS_C_NO_CONTEXT;

        // NOTE this defined elements is inherited from hiseceasy
        const std::string elements = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01";
        gss_OID_desc_struct gssUserName;
        rtMsg = MakeGssOIDDescStruct(elements, gssUserName);
        if (rtMsg.mResult != 0) {
            if (gssUserName.elements != nullptr) {
                free(gssUserName.elements);
                gssUserName.elements = nullptr;
            }
            CCSEC_LOG_ERROR("|ServerInit|END|returnF|" << rtMsg.mMessage);
            return {KrbRc::CDF_ERROR, "make gssOIDDescStruct error"};
        }
        gss_buffer_desc serviceNameBuffer;
        rtMsg = MakeGssBufferDesc(servicePrincipleName, serviceNameBuffer);
        if (rtMsg.mResult != 0) {
            freeGssUserNameAndServiceNameBuffer(gssUserName, serviceNameBuffer);
            CCSEC_LOG_ERROR("|ServerInit|END|returnF|" << rtMsg.mMessage);
            return {KrbRc::CDF_ERROR, "make gssBufferDesc error"};
        }

        // Import name to gssServiceName_
        majorStatus = Krb5Wrapper::gss_import_name(&minorStatus, &serviceNameBuffer, &gssUserName, &gssServiceName_);
        if (majorStatus != GSS_S_COMPLETE) {
            kerberosContext_.KerberosDestroyKeytab();
            auto ret = KrbResult(KrbRc::CDF_ERROR, "gss_import_name Failed");
            // uint32_t minorStatus;
            freeGssUserNameAndServiceNameBuffer(gssUserName, serviceNameBuffer);
            CCSEC_LOG_ERROR("|ServerInit|END|returnF|" << ret.mMessage);
            return ret;
        }

        // Try to acqure credential with gssapi
        majorStatus = Krb5Wrapper::gss_acquire_cred(&minorStatus, gssServiceName_, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                                    GSS_C_ACCEPT, &serverCredentials_, nullptr, nullptr);
        if (majorStatus != GSS_S_COMPLETE) {
            Krb5Wrapper::gss_release_name(&minorStatus, &gssServiceName_);
            kerberosContext_.KerberosDestroyKeytab();
            // uint32_t minorStatus;
            freeGssUserNameAndServiceNameBuffer(gssUserName, serviceNameBuffer);
            CCSEC_LOG_ERROR("|ServerInit|END|returnF|gss_acquire_cred Failed");
            return {KrbRc::CDF_ERROR, "ServerInit gss_acquire_cred error"};
        }

        // Add mutex lock
        g_initial = true;
        freeGssUserNameAndServiceNameBuffer(gssUserName, serviceNameBuffer);
        CCSEC_LOG_INFO("|ServerInit|END|returnS|ServerInit success");
        return {KrbRc::CDF_OK, "ServerInit success"};
    }

    KrbResult ServerAuth([[maybe_unused]] int flags, const std::string &credIn, char **credOut, uint32_t *credLenOut)
    {
        if (!g_initial) {
            CCSEC_LOG_ERROR("|ServerAuth|END|returnF|Server is not inited");
            return {KrbRc::CDF_UNINITED, "Server is not inited"};
        }
        if (credOut == nullptr || credLenOut == nullptr) {
            CCSEC_LOG_ERROR("|ServerAuth|END|returnF|Output parameters are null");
            return {KrbRc::CDF_ERROR, "Output parameters are null"};
        }
        if (credIn.empty() || credIn.size() > MAX_FILE_SIZE) {
            auto ret = KrbResult(KrbRc::CDF_INVALID_PARAM, "ServerAuth parameter error");
            CCSEC_LOG_ERROR("|ServerAuth|END|returnF|" << ret.mMessage);
            return ret;
        }

        std::lock_guard<std::mutex> guard(serverAuthMutex_);
        OM_uint32 majorStatus;
        OM_uint32 minorStatus = 0;

        std::string cred_copy = credIn;
        gss_buffer_desc inputToken{cred_copy.size(), cred_copy.data()};
        gss_buffer_desc outputToken = {0, nullptr};

        if (serverCredOut_ != nullptr) {
            free(serverCredOut_);
            serverCredOut_ = nullptr;
        }

        gssServerContext_ = nullptr;
        majorStatus =
            Krb5Wrapper::gss_accept_sec_context(&minorStatus, &gssServerContext_, serverCredentials_, &inputToken,
                                                nullptr, nullptr, nullptr, &outputToken, nullptr, nullptr, nullptr);

        // handle outputToken
        KrbResult authResult = HandleServerAuthOutputToken(outputToken, credOut, credLenOut);
        if (authResult.mResult != static_cast<uint32_t>(KrbRc::CDF_OK)) {
            if (gssServerContext_ != nullptr) {
                Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssServerContext_, nullptr);
            }
            Krb5Wrapper::gss_release_buffer(&minorStatus, &outputToken);
            CCSEC_LOG_ERROR("|ServerAuth|END|returnF|failed to get output token, " << authResult.mMessage);
            return authResult;
        }

        KrbResult ar = CheckReturn(majorStatus, minorStatus);
        if (ar.mResult != 0) {
            return ar;
        }

        KrbResult ret = ServerGetClientPrincipal();
        Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssServerContext_, nullptr);

        return ret;
    }

    bool CheckFile(const std::string &configPath)
    {
        std::array<char, PATH_MAX + 1> confRealPath;
        if (configPath.size() > PATH_MAX) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|The file path exceeds the maximum value set by PATH_MAX");
            return false;
        }

        if (realpath(configPath.c_str(), confRealPath.data()) == nullptr) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|Get realpath failed");
            return false;
        }

        struct stat statBuf {};
        auto ret = stat(confRealPath.data(), &statBuf);
        if (ret != 0) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|stat failed");
            return false;
        }

        if (statBuf.st_size <= 0 || statBuf.st_size > MAX_FILE_SIZE) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|file size is invalid: " << statBuf.st_size);
            return false;
        }

        return true;
    }

    static bool GetKeyTabVal(const std::string &path, char **keytab, uint32_t &keytabLen)
    {
        if (keytab == nullptr) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|Output parameter keytab is null");
            return false;
        }
        char *tempKeyTab;
        FILE *fp;
        keytabLen = 0;
        std::array<char, PATH_MAX + 1> filePath;

        if (realpath(path.c_str(), filePath.data()) == nullptr) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|Get realpath for ClientKeyTab failed");
            return false;
        }

        fp = fopen(filePath.data(), "rb");
        if (fp == nullptr) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|Failed to read Kerberos keytab file: " << filePath.data());
            return false;
        }

        if (fseek(fp, 0L, SEEK_END) != 0) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|fseek(fp, 0L, SEEK_END) != 0");
            fclose(fp);
            return false;
        }
        auto fileSize = ftell(fp);
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|fseek(fp, 0L, SEEK_SET) != 0");
            fclose(fp);
            return false;
        }

        if (fileSize <= 0 || fileSize > MAX_FILE_SIZE) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|keytab size is invalid: " << std::to_string(fileSize));
            fclose(fp);
            return false;
        }
        if (!ReadKeyTabContent(fp, fileSize, &tempKeyTab)) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|failed to read keytab content");
            fclose(fp);
            return false;
        }
        fclose(fp);
        *keytab = tempKeyTab;
        keytabLen = static_cast<uint32_t>(fileSize);
        return true;
    }

    static bool ReadKeyTabContent(FILE *fp, int64_t fileSize, char **keyTabBuf)
    {
        if (keyTabBuf == nullptr) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|keyTabBuf is null.");
            return false;
        }
        *keyTabBuf = static_cast<char *>(malloc(fileSize));
        if (*keyTabBuf == nullptr) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|Failed to malloc memory for keytab.");
            return false;
        }

        if (fread(*keyTabBuf, fileSize, 1, fp) != 1) {
            CCSEC_LOG_ERROR("|GetKeyTabVal|END|returnF|fread(tmp, fileSize, 1, fp) != 1");
            free(*keyTabBuf);
            *keyTabBuf = nullptr;
            return false;
        }
        return true;
    }

    static uint64_t GetRandomValue()
    {
        return GetRandomValueInternal();
    }

    static bool ReadCipherFromFile(const std::string &path, std::string &fileContent)
    {
        auto [ret, realPath] = FileUtils::CanonicalPath(path);
        if (!ret) {
            CCSEC_LOG_ERROR("|open file|END|returnF|failed to get canonical path, given: " << path);
            return false;
        }

        std::string errMsg;
        if (!FileUtils::CheckUserAccess(realPath, R_OK) || !FileUtils::IsFileValid(realPath, errMsg)) {
            CCSEC_LOG_ERROR("|open file|END|returnF|failed to read path, given: " << path);
            return false;
        }

        if (FileUtils::CheckUserAccess(realPath, R_OK)) {
            CCSEC_LOG_ERROR("|open file|END|returnF|failed to read path, given: " << path);
            return false;
        }

        std::ifstream in(realPath);
        if (!in.is_open()) {
            CCSEC_LOG_ERROR("|ReadCipherFromFile|END|returnF|Failed to open the keypass file");
            return false;
        }
        std::stringstream buffer;
        buffer << in.rdbuf();
        fileContent = buffer.str();
        in.close();
        return true;
    }

    static bool GetKerberosKeytab(const std::string &path, char **outKeyTab, uint32_t *length, bool keyTabEncrypted)
    {
        if (outKeyTab == nullptr || length == nullptr) {
            CCSEC_LOG_ERROR("|GetKerberosKeytab|END|returnF|outKeyTab or length is null");
            return false;
        }
        if (path.size() > PATH_MAX) {
            CCSEC_LOG_ERROR("|GetKerberosKeytab|END|returnF|path is too long");
            return false;
        }
        if (!keyTabEncrypted) {
            char *keytab = nullptr;
            uint32_t keytabLen = 0;
            if (!GetKeyTabVal(path, &keytab, keytabLen)) {
                return false;
            }
            *outKeyTab = keytab;
            *length = keytabLen;
            return true;
        }

        std::string kerberosKeytab;
        if (!ReadCipherFromFile(path, kerberosKeytab)) {
            return false;
        }
        if (kerberosKeytab.length() > MAX_KEYPASS_LEN) {
            CCSEC_LOG_ERROR("|GetKerberosKeytab|END|returnF|length of keypass is too long: "
                            << kerberosKeytab.length() << ", max: " << MAX_KEYPASS_LEN);
            return false;
        }

        char *plain = static_cast<char *>(malloc(kerberosKeytab.length()));
        if (plain == nullptr) {
            CCSEC_LOG_ERROR("|GetKerberosKeytab|END|returnF|malloc memory for cryption failed");
            return false;
        }
        auto plainLength = kerberosKeytab.length();
        (void)memset_s(plain, plainLength, 0, plainLength);

        auto cryptor = KmCryptor(DEFAULT_KRB_KEY_MANAGER_TY);
        auto [rc, plaintext] = cryptor.Decrypt(KRB_DEFAULT_CRYPTO_SYMALG, kerberosKeytab, KRB_DEFAULT_DOMAIN_ID);
        if (memcpy_s(plain, plainLength, plaintext.data(), plaintext.size()) != EOK) {
            (void)memset_s(plain, plainLength, 0, plainLength);
            free(plain);
            plain = nullptr;
            CCSEC_LOG_ERROR("|GetKerberosKeytab|END|returnF|memcpy_s error");
            return false;
        }
        *outKeyTab = plain;
        *length = static_cast<uint32_t>(plainLength);
        return true;
    }

private:
    KrbCtx kerberosContext_;
    std::mutex serverAuthMutex_;

    krb5_keytab_entry keytabEntry_;
    gss_name_t gssServiceName_ = nullptr;
    gss_ctx_id_t gssServerContext_ = nullptr;
    char *serverCredOut_ = nullptr;
    std::string clientPrincipName_;
    gss_cred_id_t serverCredentials_ = nullptr;

    KrbResult ServerGetClientPrincipal()
    {
        OM_uint32 majorStatus;
        OM_uint32 minorStatus = 0;
        gss_name_t tmpClientName = nullptr;
        gss_name_t tmpServerName = nullptr;
        char *clientPrincipal = nullptr;
        gss_buffer_desc clientNameToken;

        majorStatus = Krb5Wrapper::gss_inquire_context(&minorStatus, gssServerContext_, &tmpClientName, &tmpServerName,
                                                       nullptr, nullptr, nullptr, nullptr, nullptr);
        if (majorStatus != GSS_S_COMPLETE) {
            std::string errMsg = "gss_inquire_context failed, majorStatus:" + std::to_string(majorStatus) +
                                 ", minorStatus:" + std::to_string(minorStatus);
            CCSEC_LOG_ERROR("|ServerGetClientPrincipal|END|returnF|" << errMsg);
            return {minorStatus != 0U ? minorStatus : majorStatus, errMsg};
        }

        majorStatus = Krb5Wrapper::gss_display_name(&minorStatus, tmpClientName, &clientNameToken, nullptr);
        if (majorStatus != GSS_S_COMPLETE) {
            FreeClientPrincipalRes(minorStatus, tmpClientName, tmpServerName, clientNameToken, clientPrincipal);
            std::string errMsg = "gss_display_name failed";
            CCSEC_LOG_ERROR("|ServerGetClientPrincipal|END|returnF|" << errMsg);
            return {minorStatus != 0U ? minorStatus : majorStatus, errMsg};
        }

        if (clientNameToken.length <= 0) {
            FreeClientPrincipalRes(minorStatus, tmpClientName, tmpServerName, clientNameToken, clientPrincipal);
            std::string errMsg = "clientNameToken.length failed";
            CCSEC_LOG_ERROR("|ServerGetClientPrincipal|END|returnF|" << errMsg);
            return {KrbRc::CDF_ERROR, errMsg};
        }
        clientPrincipal = static_cast<char *>(malloc(clientNameToken.length + 1));
        if (clientPrincipal == nullptr) {
            FreeClientPrincipalRes(minorStatus, tmpClientName, tmpServerName, clientNameToken, clientPrincipal);
            std::string errMsg = "clientPrincipal malloc failed";
            CCSEC_LOG_ERROR("|ServerGetClientPrincipal|END|returnF|" << errMsg);
            return {ENOMEM, errMsg};
        }

        if (memcpy_s(clientPrincipal, clientNameToken.length, clientNameToken.value, clientNameToken.length) != EOK) {
            FreeClientPrincipalRes(minorStatus, tmpClientName, tmpServerName, clientNameToken, clientPrincipal);
            std::string errMsg = "clientPrincipal malloc failed";
            CCSEC_LOG_ERROR("|ServerGetClientPrincipal|END|returnF|" << errMsg);
            return {ENOMEM, errMsg};
        }
        clientPrincipal[clientNameToken.length] = '\0';
        clientPrincipName_ = clientPrincipal;

        FreeClientPrincipalRes(minorStatus, tmpClientName, tmpServerName, clientNameToken, clientPrincipal);
        CCSEC_LOG_INFO("|ServerGetClientPrincipal|END|returnS|ServerGetClientPrincipal succeed");
        return {KrbRc::CDF_OK, "ServerGetClientPrincipal succeed"};
    }

    static void FreeClientPrincipalRes(OM_uint32 &minorStatus, gss_name_t &tmpClientName, gss_name_t &tmpServerName,
                                       gss_buffer_desc &clientNameToken, char *&clientPrincipal)
    {
        // 释放 tmpClientName
        if (tmpClientName != nullptr) {
            Krb5Wrapper::gss_release_name(&minorStatus, &tmpClientName);
        }

        // 释放 tmpServerName
        if (tmpServerName != nullptr) {
            Krb5Wrapper::gss_release_name(&minorStatus, &tmpServerName);
        }

        // 释放 clientNameToken 的内容
        if (clientNameToken.value != nullptr) {
            Krb5Wrapper::gss_release_buffer(&minorStatus, &clientNameToken);
        }

        // 释放 clientPrincipal 的内存
        if (clientPrincipal != nullptr) {
            free(clientPrincipal);
            clientPrincipal = nullptr; // 将指针置为空，防止重复释放
        }
    }

    KrbResult HandleServerAuthOutputToken(gss_buffer_desc &outputToken, char **credOut, uint32_t *credLenOut)
    {
        if (credOut == nullptr || credLenOut == nullptr) {
            return {KrbRc::CDF_ERROR, "Output parameters are null"};
        }
        // 检查outputToken有效性
        if (outputToken.length == 0 || outputToken.value == nullptr) {
            return {KrbRc::CDF_ERROR, "outputToken is empty"};
        }

        // 释放之前分配的内存
        if (serverCredOut_ != nullptr) {
            free(serverCredOut_);
            serverCredOut_ = nullptr;
        }

        // 分配新的内存
        serverCredOut_ = static_cast<char *>(calloc(1, outputToken.length));
        if (serverCredOut_ == nullptr) {
            return {KrbRc::CDF_ERROR, "malloc failed"};
        }

        // 复制数据
        if (memcpy_s(serverCredOut_, outputToken.length, outputToken.value, outputToken.length) != EOK) {
            // 复制失败，释放内存
            free(serverCredOut_);
            serverCredOut_ = nullptr;
            return {KrbRc::CDF_ERROR, "memcpy_s failed"};
        }

        // 更新输出参数
        *credOut = serverCredOut_;
        *credLenOut = outputToken.length;

        // 释放GSS缓冲区
        OM_uint32 minorStatus = 0;
        Krb5Wrapper::gss_release_buffer(&minorStatus, &outputToken);

        return {KrbRc::CDF_OK, "OK"};
    }

    KrbResult CheckReturn(OM_uint32 majorStatus, OM_uint32 minorStatus)
    {
        if ((majorStatus != GSS_S_COMPLETE) && (majorStatus != GSS_S_CONTINUE_NEEDED)) {
            Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssServerContext_, nullptr);
            std::string err = "ServerAuth Failed, minorStatus[" + std::to_string(minorStatus) + "], majorStatus[" +
                              std::to_string(majorStatus) + "]";
            CCSEC_LOG_ERROR("|CheckReturn|END|returnF|" << err);
            return {minorStatus != 0U ? minorStatus : majorStatus, err};
        }

        if (majorStatus == GSS_S_CONTINUE_NEEDED) {
            Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssServerContext_, nullptr);
            std::string err = "ServerAuth Failed, minorStatus[" + std::to_string(minorStatus) + "], majorStatus[" +
                              std::to_string(majorStatus) + "]";
            CCSEC_LOG_ERROR("|CheckReturn|END|returnF|" << err);
            return {minorStatus != 0U ? minorStatus : majorStatus, err};
        }
        CCSEC_LOG_INFO("|CheckReturn|END|returnS|checkout success");
        return {KrbRc::CDF_OK, "checkout success"};
    }
};

// ---------------------
// PIMP Function Parsing
// ---------------------
KrbServer::KrbServer() : impl_(std::make_unique<KrbServer::Impl>())
{}

KrbServer::~KrbServer() = default;

KrbResult KrbServer::ServerInit(const std::string &servicePrincipleName, const std::string &keyTable)
{
    return impl_->ServerInit(servicePrincipleName, keyTable);
}

KrbResult KrbServer::ServerAuth(int flags, const std::string &credIn, char **credOut, uint32_t *credLenOut)
{
    return impl_->ServerAuth(flags, credIn, credOut, credLenOut);
}

bool KrbServer::ResetInternalKeyTable()
{
    return impl_->ResetInternalKeyTable();
}
bool KrbServer::GetKerberosKeytab(const std::string &path, char **outKeyTab, uint32_t *length, bool keyTabEncrypted)
{
    return impl_->GetKerberosKeytab(path, outKeyTab, length, keyTabEncrypted);
}

bool KrbServer::CheckFile(const std::string &configPath)
{
    return impl_->CheckFile(configPath);
}

std::shared_ptr<KrbServer> KrbServer::GetAuthentication([[maybe_unused]] const std::string &name)
{
    if (name != KERBEROS) {
        CCSEC_LOG_ERROR("|GetAuthentication|END|returnF|name is not kerberos");
        return nullptr;
    } else {
        return std::make_shared<KrbServer>();
    }
}

} // namespace cdf
