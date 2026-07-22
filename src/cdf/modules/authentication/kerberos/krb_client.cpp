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

#include "cdf/modules/authentication/kerberos/krb_client.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "krb5/krb5.h"
#include "securec.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/custom_logger.h"
#include "cdf/connector/krb5_wrapper.h"
#include "cdf/modules/authentication/kerberos/krb_ctx.h"

namespace cdf {

// ---------------------------
// PIMP Private Implementation
// ---------------------------

class KrbClient::Impl {
public:
    Impl() = default;

    ~Impl()
    {
        OM_uint32 minorStatus = 0;

        if (gssClientName_ != nullptr) {
            Krb5Wrapper::gss_release_name(&minorStatus, &gssClientName_);
        }

        if (gssServiceName_ != nullptr) {
            Krb5Wrapper::gss_release_name(&minorStatus, &gssServiceName_);
        }

        if (clientCredentials_ != nullptr) {
            Krb5Wrapper::gss_release_cred(&minorStatus, &clientCredentials_);
        }

        if (gssClientContext_ != nullptr) {
            Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssClientContext_, nullptr);
        }

        kerberosContext_.KerberosDestroyCCache();
    }

    bool InitParam()
    {
        (void)memset_s(&keytabEntry_, sizeof(krb5_keytab_entry), 0, sizeof(krb5_keytab_entry));
        return true;
    }

    KrbResult ClientInit(const std::string &inClientName, const std::string &inServiceName, const std::string &keyTable)
    {
        if (inClientName.empty() || inServiceName.empty() || keyTable.empty() ||
            inClientName.size() > MAX_ALLOWED_NAME_LENGTH || inServiceName.size() > MAX_ALLOWED_NAME_LENGTH ||
            keyTable.size() > MAX_FILE_SIZE) {
            auto ret = KrbResult(KrbRc::CDF_INVALID_PARAM, "Invalid parameter, client/server name may be "
                                                                "empty or key table is empty or too large.");
            CCSEC_LOG_ERROR("|ClientInit|END|returnF|Return code: " << ret.mMessage);
            return ret;
        }

        gssClientContext_ = nullptr;
        clientCredentials_ = nullptr;

        KeytabValue keytabValue = {keyTable};

        KrbResult authAr = kerberosContext_.KerberosInitCCache(keytabValue, inClientName);
        if (authAr.mResult != 0) {
            CCSEC_LOG_ERROR("|ClientInit|END|returnF|" << authAr.mMessage);
            return authAr;
        }
        authAr = ClientInitClient(inClientName);
        if (authAr.mResult != 0) {
            CCSEC_LOG_ERROR("|ClientInit|END|returnF|" << authAr.mMessage);
            return authAr;
        }
        authAr = ClientInitServer(inServiceName);
        if (authAr.mResult != 0) {
            CCSEC_LOG_ERROR("|ClientInit|END|returnF|" << authAr.mMessage);
            return authAr;
        }
        CCSEC_LOG_INFO("|ClientInit|END|returnS|ClientInit Succeed");
        return {KrbRc::CDF_OK, "ClientInit Succeed"};
    }

    std::pair<KrbResult, std::vector<uint8_t>> ClientGetCred([[maybe_unused]] int flags)
    {
        std::vector<uint8_t> outCred;
        OM_uint32 majorStatus;
        OM_uint32 minorStatus = 0;
        OM_uint32 actualFlags = 0;
        gss_buffer_t inputTokenPtr = nullptr;
        std::string retMsg;

        majorStatus = GSS_S_CONTINUE_NEEDED;
        gss_buffer_desc outputToken = {0, nullptr};
        OM_uint32 requestedFlags =
            (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);
        if (gssClientContext_ != nullptr) {
            return {{1, "Client has already been inited"}, {}};
        }

        majorStatus = Krb5Wrapper::gss_init_sec_context(
            &minorStatus, clientCredentials_, &gssClientContext_, gssServiceName_, GSS_C_NULL_OID, requestedFlags,
            GSS_C_INDEFINITE, nullptr, inputTokenPtr, nullptr, &outputToken, &actualFlags, nullptr);
        if ((outputToken.length > 0) && (outputToken.value != nullptr)) {
            outCred.resize(outputToken.length);
            if (memcpy_s(outCred.data(), outCred.size(), outputToken.value, outputToken.length) != EOK) {
                if (gssClientContext_ != nullptr) {
                    Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssClientContext_, nullptr);
                }
                retMsg = "memcpy_s error";
                CCSEC_LOG_ERROR("|ClientGetCred|END|returnF|" << retMsg);
                return {{KrbRc::CDF_ERROR, retMsg}, {}};
            }
            Krb5Wrapper::gss_release_buffer(&minorStatus, &outputToken);
            CCSEC_LOG_INFO("|ClientGetCred|END|returnS|ClientGetCred succeed");
            return {{KrbRc::CDF_OK, "ClientGetCred succeed"}, outCred};
        } else {
            if (gssClientContext_ != nullptr) {
                Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssClientContext_, nullptr);
            }
            retMsg = "gss_init_sec_context error, majorStatus:" + std::to_string(majorStatus) +
                     ", minorStatus:" + std::to_string(minorStatus);
            CCSEC_LOG_ERROR("|ClientGetCred|END|returnF|" << retMsg);
            return {{KrbRc::CDF_ERROR, retMsg}, {}};
        }
    }

    KrbResult ClientAuthServer([[maybe_unused]] int flags, char *cred, uint32_t credLen)
    {
        if ((cred == nullptr) || (credLen == 0) || (credLen > static_cast<uint32_t>(MAX_FILE_SIZE))) {
            auto ret = KrbResult(KrbRc::CDF_INVALID_PARAM, "ClientAuthServer parameter error");
            CCSEC_LOG_ERROR("|ClientAuthServer|END|returnF|" << ret.mMessage);
            return ret;
        }
        OM_uint32 majorStatus;
        OM_uint32 minorStatus = 0;
        OM_uint32 actualFlags = 0;
        gss_buffer_desc inputToken = {credLen, cred};
        gss_buffer_t inputTokenPtr = &inputToken;

        gss_buffer_desc outputToken = {0, nullptr};
        OM_uint32 requestedFlags =
            (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);

        majorStatus = Krb5Wrapper::gss_init_sec_context(
            &minorStatus, clientCredentials_, &gssClientContext_, gssServiceName_, GSS_C_NULL_OID, requestedFlags,
            GSS_C_INDEFINITE, nullptr, inputTokenPtr, nullptr, &outputToken, &actualFlags, nullptr);

        if (clientCredentials_ != nullptr) {
            Krb5Wrapper::gss_release_cred(&minorStatus, &clientCredentials_);
        }
        if (majorStatus == GSS_S_CONTINUE_NEEDED) {
            auto ret = KrbResult(KrbRc::CDF_ERROR, "ClientAuthServer Failed need continue");
            Krb5Wrapper::gss_release_buffer(&minorStatus, &outputToken);
            CCSEC_LOG_ERROR("|ClientAuthServer|END|returnF|" << ret.mMessage);
            return ret;
        }
        if (majorStatus == GSS_S_COMPLETE) {
            auto ret = KrbResult(KrbRc::CDF_OK, "ClientAuthServer Succeed");
            CCSEC_LOG_INFO("|ClientAuthServer|END|returnS|" << ret.mMessage);
            Krb5Wrapper::gss_release_buffer(&minorStatus, &outputToken);
            return ret;
        } else {
            Krb5Wrapper::gss_release_buffer(&minorStatus, &outputToken);
            if (gssClientContext_ != nullptr) {
                Krb5Wrapper::gss_delete_sec_context(&minorStatus, &gssClientContext_, nullptr);
            }
            std::string errMsg = "ClientAuthServer unknown error, majorStatus:" + std::to_string(majorStatus) +
                                 ", minorStatus:" + std::to_string(minorStatus);
            auto ret = KrbResult(KrbRc::CDF_ERROR, errMsg);
            CCSEC_LOG_ERROR("|ClientAuthServer|END|returnF|" << errMsg);
            return ret;
        }
    }

private:
    KrbResult ClientInitClient(const std::string &inClientName)
    {
        OM_uint32 majorStatus;
        OM_uint32 minorStatus = 0;
        OM_uint32 timeReq = 0;
        static char elements[] = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01";

        // 辅助函数：安全释放 clientNameBuffer
        auto CleanupBuffer = [](gss_buffer_desc &buffer) {
            if (buffer.value != nullptr) {
                (void)memset_s(buffer.value, buffer.length, 0, buffer.length);
                free(buffer.value);
                buffer.value = nullptr;
                buffer.length = 0;
            }
        };

        gss_OID_desc_struct gssUserName = {10UL, static_cast<void *>(elements)};
        gss_buffer_desc clientNameBuffer;
        clientNameBuffer.length = inClientName.size();
        clientNameBuffer.value = malloc(clientNameBuffer.length);
        if (clientNameBuffer.value == nullptr) {
            kerberosContext_.KerberosDestroyCCache();
            std::string errMsg = "malloc Failed";
            CCSEC_LOG_ERROR("|ClientInitClient|END|returnF|" << errMsg);
            return {1, errMsg};
        }

        if (memcpy_s(clientNameBuffer.value, clientNameBuffer.length, inClientName.c_str(), inClientName.size()) !=
            EOK) {
            kerberosContext_.KerberosDestroyCCache();
            std::string errMsg = "memcpy_s error";
            CCSEC_LOG_ERROR("|ClientInitClient|END|returnF|" << errMsg);
            CleanupBuffer(clientNameBuffer);
            return {1, errMsg};
        }
        majorStatus = Krb5Wrapper::gss_import_name(&minorStatus, &clientNameBuffer, static_cast<gss_OID>(&gssUserName),
                                                   &gssClientName_);
        if (majorStatus != GSS_S_COMPLETE) {
            kerberosContext_.KerberosDestroyCCache();
            CleanupBuffer(clientNameBuffer);
            std::string errMsg = "gss_import_name(inClientName) Failed";
            CCSEC_LOG_ERROR("|ClientInitClient|END|returnF|" << errMsg);
            return {KrbRc::CDF_ERROR, errMsg};
        }

        majorStatus = Krb5Wrapper::gss_acquire_cred(&minorStatus, gssClientName_, timeReq, nullptr, GSS_C_INITIATE,
                                                    &clientCredentials_, nullptr, nullptr);
        if (majorStatus != GSS_S_COMPLETE) {
            Krb5Wrapper::gss_release_name(&minorStatus, &gssClientName_);
            kerberosContext_.KerberosDestroyCCache();
            CleanupBuffer(clientNameBuffer);
            std::string errMsg = "gss_acquire_cred Failed";
            CCSEC_LOG_ERROR("|ClientInitClient|END|returnF|" << errMsg);
            return {KrbRc::CDF_ERROR, errMsg};
        }
        CleanupBuffer(clientNameBuffer);
        CCSEC_LOG_INFO("|ClientInitClient|END|returnS|ClientInitClient Succeed");
        return {KrbRc::CDF_OK, "ClientInitClient Succeed"};
    }

    static bool inline Krb5NameFormatCheckHack(const std::string &name)
    {
        krb5_context tmpCtx;
        krb5_principal tmpOutPtr;
        if (Krb5Wrapper::krb5_init_context(&tmpCtx) != 0) {
            return false;
        }
        if (Krb5Wrapper::krb5_parse_name(tmpCtx, name.c_str(), &tmpOutPtr) != 0) {
            Krb5Wrapper::krb5_free_principal(tmpCtx,
                                             tmpOutPtr); // free principal
            Krb5Wrapper::krb5_free_context(tmpCtx);      // free context
            return false;
        } else {
            Krb5Wrapper::krb5_free_principal(tmpCtx,
                                             tmpOutPtr); // free principal
            Krb5Wrapper::krb5_free_context(tmpCtx);      // free context
            return true;
        }
    }

    KrbResult ClientInitServer(const std::string &inServiceName)
    {
        if (!Krb5NameFormatCheckHack(inServiceName)) {
            KrbResult ret;
            ret.mMessage = "Invalid inServiceName: " + inServiceName;
            ret.mResult = 1;
            return ret;
        }
        OM_uint32 majorStatus;
        OM_uint32 minorStatus = 0;
        char elements[] = "\052\206\110\206\367\022\001\002\002\001";

        gss_OID_desc_struct gssNTPrincipalName = {10UL, static_cast<void *>(elements)};
        gss_buffer_desc serverNameBuffer;
        serverNameBuffer.length = inServiceName.size();
        serverNameBuffer.value = malloc(serverNameBuffer.length);
        if (serverNameBuffer.value == nullptr) {
            std::string errMsg = "malloc Failed";
            CCSEC_LOG_ERROR("|ClientInitServer|END|returnF|" << errMsg);
            return {1, errMsg};
        }

        if (memcpy_s(serverNameBuffer.value, serverNameBuffer.length, inServiceName.c_str(), inServiceName.size()) !=
            EOK) {
            free(serverNameBuffer.value);
            serverNameBuffer.value = nullptr;
            std::string errMsg = "memcpy_s error";
            CCSEC_LOG_ERROR("|ClientInitServer|END|returnF|" << errMsg);
            return {1, errMsg};
        }
        majorStatus = Krb5Wrapper::gss_import_name(&minorStatus, &serverNameBuffer,
                                                   static_cast<gss_OID>(&gssNTPrincipalName), &gssServiceName_);
        if (majorStatus != GSS_S_COMPLETE) {
            Krb5Wrapper::gss_release_name(&minorStatus, &gssClientName_);
            Krb5Wrapper::gss_release_name(&minorStatus, &gssServiceName_);
            Krb5Wrapper::gss_release_cred(&minorStatus, &clientCredentials_);
            kerberosContext_.KerberosDestroyCCache();
            std::string errMsg = "gss_import_name(inServiceName) Failed";
            CCSEC_LOG_ERROR("|ClientInitServer|END|returnF|" << errMsg);
            memset_s(serverNameBuffer.value, serverNameBuffer.length, 0, serverNameBuffer.length);
            free(serverNameBuffer.value);
            serverNameBuffer.value = nullptr;
            serverNameBuffer.length = 0;
            return {KrbRc::CDF_ERROR, errMsg};
        }
        free(serverNameBuffer.value);
        serverNameBuffer.value = nullptr;
        CCSEC_LOG_INFO("|ClientInitServer|END|returnS|ClientInitServer Succeed");
        return {KrbRc::CDF_OK, "ClientInitServer Succeed"};
    }

    krb5_keytab_entry keytabEntry_;
    gss_name_t gssClientName_ = nullptr;
    gss_name_t gssServiceName_ = nullptr;
    gss_ctx_id_t gssClientContext_ = nullptr;
    gss_cred_id_t clientCredentials_ = nullptr;
    KrbCtx kerberosContext_;
};

// ---------------------
// PIMP Function Parsing
// ---------------------

KrbClient::KrbClient() : impl_(std::make_unique<KrbClient::Impl>())
{}

KrbClient::~KrbClient() = default;

bool KrbClient::InitParam()
{
    return impl_->InitParam();
}

KrbResult KrbClient::ClientInit(const std::string &inClientName, const std::string &inServiceName,
                                const std::string &keyTable)
{
    return impl_->ClientInit(inClientName, inServiceName, keyTable);
}

std::pair<KrbResult, std::vector<uint8_t>> KrbClient::ClientGetCred(int flags)
{
    return impl_->ClientGetCred(flags);
}

KrbResult KrbClient::ClientAuthServer(int flags, char *cred, uint32_t credLen)
{
    return impl_->ClientAuthServer(flags, cred, credLen);
}

std::shared_ptr<KrbClient> KrbClient::GetAuthentication(const std::string &name)
{
    if (name != KERBEROS) {
        CCSEC_LOG_ERROR("|GetAuthentication|END|returnF|name is not kerberos");
        return nullptr;
    } else {
        return std::make_shared<KrbClient>();
    }
}

} // namespace cdf
