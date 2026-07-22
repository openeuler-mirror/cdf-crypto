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

#include "cdf/modules/authentication/kerberos/krb_ctx.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <string>

#include "krb5/krb5.h"
#include "securec.h"

#include "cdf/base/custom_logger.h"
#include "cdf/connector/krb5_wrapper.h"

namespace cdf {

// ---------------------------
// PIMP Private Implementation
// ---------------------------

class KrbCtx::Impl {
public:
    Impl() = default;
    ~Impl() = default;

    KrbResult KerberosInitKeytab(const KeytabValue &keytabValue, const std::string &inPrincipal,
                                 const std::string &memoryKeytabName = std::string(KRB5KTNAME))
    {
        KrbResult ar = KerberosInit(inPrincipal);
        if (ar.mResult != 0) {
            return ar;
        }

        if (memoryKeytabName.size() > MAX_KEYTAB_NAME_LEN) {
            return {1, ""};
        }

        if (setenv("KRB5_KTNAME", memoryKeytabName.c_str(), 1) != 0) {
            (void)KerberosUninit();
            return {1, ""};
        }

        if (Krb5Wrapper::krb5_kt_resolve(krb5Context_, memoryKeytabName.c_str(), &keytab_) != 0) {
            (void)KerberosUninit();
            return {1, ""};
        }

        ar = KerberosGetEntry(keytabValue, 0, 0, keytabEntry_);
        if (ar.mResult != 0) {
            Krb5Wrapper::krb5_kt_close(krb5Context_, keytab_);
            keytab_ = nullptr;
            (void)KerberosUninit();
            return ar;
        }

        if (Krb5Wrapper::krb5_kt_add_entry(krb5Context_, keytab_, &keytabEntry_) != 0) {
            Krb5Wrapper::krb5_kt_free_entry(krb5Context_, &keytabEntry_);
            keytabEntry_.principal = nullptr;
            Krb5Wrapper::krb5_kt_close(krb5Context_, keytab_);
            keytab_ = nullptr;
            (void)KerberosUninit();
            return {1, "krb5_kt_add_entry failed"};
        }

        return {0, "KerberosInitKeytab Succeed"};
    }

    KrbResult KerberosInitCCache(const KeytabValue &keytabValue, const std::string &inPrincipal,
                                 const std::string &memoryKeytabName = std::string(KRB5KTNAME),
                                 const std::string &inkrb5ccname = std::string(KRB5CCNAME))
    {
        if (memoryKeytabName.size() > MAX_KEYTAB_NAME_LEN || inkrb5ccname.size() > MAX_KEYTAB_NAME_LEN) {
            return {1, ""};
        }

        auto ar = KerberosInitKeytab(keytabValue, inPrincipal, memoryKeytabName);
        if (ar.mResult != 0) {
            return ar;
        }

        if (setenv("KRB5CCNAME", inkrb5ccname.c_str(), 1) != 0) {
            (void)KerberosDestroyKeytab();
            return {1, "could not set KRB5CCNAME env"};
        }

        if (Krb5Wrapper::krb5_cc_default(krb5Context_, &ccache_) != 0) {
            Krb5Wrapper::krb5_cc_destroy(krb5Context_, ccache_);
            ccache_ = nullptr;
            (void)KerberosDestroyKeytab();
            return {1, "unable to get default credentials cache"};
        }

        if (Krb5Wrapper::krb5_get_init_creds_opt_alloc(krb5Context_, &opts_) != 0) {
            Krb5Wrapper::krb5_cc_destroy(krb5Context_, ccache_);
            ccache_ = nullptr;
            (void)KerberosDestroyKeytab();
            return {1, "unable to allocate get_init_creds_opt struct"};
        }
        auto credResult = ObtainKerberosCredentials();
        if (credResult.mResult == 0) {
            return credResult;
        }

        Krb5Wrapper::krb5_get_init_creds_opt_free(krb5Context_, opts_);
        opts_ = nullptr;
        Krb5Wrapper::krb5_cc_destroy(krb5Context_, ccache_);
        ccache_ = nullptr;
        (void)KerberosDestroyKeytab();
        return credResult;
    }

    KrbResult ObtainKerberosCredentials()
    {
        krb5_creds creds;
        (void)memset_s(&creds, sizeof(krb5_creds), 0, sizeof(krb5_creds));

        auto rc = Krb5Wrapper::krb5_get_init_creds_keytab(krb5Context_, &creds, principal_, keytab_, 0, nullptr, opts_);
        if (rc != 0) {
            Krb5Wrapper::krb5_free_cred_contents(krb5Context_, &creds);
            return {1, "unable to login from keytab"};
        }

        std::string errMessage;
        if (Krb5Wrapper::krb5_cc_initialize(krb5Context_, ccache_, principal_) != 0) {
            errMessage += "could not init ccache";
        } else if (Krb5Wrapper::krb5_cc_store_cred(krb5Context_, ccache_, &creds) != 0) {
            errMessage += "could not store creds in cache";
        } else {
            Krb5Wrapper::krb5_free_cred_contents(krb5Context_, &creds);
            return {0, "KerberosInitCcache Succeed"};
        }
        Krb5Wrapper::krb5_free_cred_contents(krb5Context_, &creds);
        return {1, errMessage};
    }

    KrbResult KerberosDestroyKeytab()
    {
        if (keytabEntry_.principal != nullptr) {
            Krb5Wrapper::krb5_kt_remove_entry(krb5Context_, keytab_, &keytabEntry_);
            Krb5Wrapper::krb5_kt_free_entry(krb5Context_, &keytabEntry_);
            keytabEntry_.principal = nullptr;
        }

        if (keytab_ != nullptr) {
            Krb5Wrapper::krb5_kt_close(krb5Context_, keytab_);
            keytab_ = nullptr;
        }

        (void)KerberosUninit();

        return {0, "KerberosDestroyKeytab succeed"};
    }

    KrbResult KerberosDestroyCCache()
    {
        if (opts_ != nullptr) {
            Krb5Wrapper::krb5_get_init_creds_opt_free(krb5Context_, opts_);
            opts_ = nullptr;
        }

        (void)KerberosDestroyKeytab();

        return {0, "KerberosDestroyCcache succeed"};
    }

    KrbResult KerberosUninit()
    {
        if (principal_ != nullptr) {
            Krb5Wrapper::krb5_free_principal(krb5Context_, principal_);
            principal_ = nullptr;
        }

        if (keytab_ != nullptr) {
            Krb5Wrapper::krb5_kt_close(krb5Context_, keytab_);
            keytab_ = nullptr;
        }

        if (ccache_ != nullptr) {
            Krb5Wrapper::krb5_cc_destroy(krb5Context_, ccache_);
            ccache_ = nullptr;
        }

        if (opts_ != nullptr) {
            Krb5Wrapper::krb5_get_init_creds_opt_free(krb5Context_, opts_);
            opts_ = nullptr;
        }

        if (krb5Context_ != nullptr) {
            Krb5Wrapper::krb5_free_context(krb5Context_);
            krb5Context_ = nullptr;
        }

        return {0, "KerberosUninit succeed"};
    }

private:
    krb5_context krb5Context_ = nullptr;
    krb5_principal principal_ = nullptr;
    krb5_keytab_entry keytabEntry_;
    krb5_keytab keytab_ = nullptr;
    krb5_ccache ccache_ = nullptr;
    krb5_get_init_creds_opt *opts_ = nullptr;

    template <typename T, std::enable_if_t<std::is_standard_layout_v<T>, int> = 0>
    int32_t KerberosRead(const KeytabValue &keytabValue, T *dst, size_t size, size_t count, uint32_t &pos) const
    {
        int32_t cnt = 0;
        for (size_t i = 0; i < count; i++) {
            if (pos + size > keytabValue.buf.size()) {
                return 0;
            }

            if (memcpy_s(dst + cnt, size, keytabValue.buf.data() + pos, size) != EOK) {
                return 0;
            }

            pos += size;
            cnt += static_cast<int32_t>(size);
        }
        return cnt;
    }

    static krb5_boolean KerberosTSAfter(krb5_timestamp a, krb5_timestamp b)
    {
        auto ua = static_cast<uint32_t>(a);
        auto ub = static_cast<uint32_t>(b);
        return ua > ub;
    }

    static krb5_boolean KerberosMoreRecent(const krb5_keytab_entry &k1, const krb5_keytab_entry &k2)
    {
        const uint32_t kMinKvno = 128;
        const uint32_t kMaxKvno = 128;
        if (!KerberosTSAfter(k2.timestamp, k1.timestamp) && k1.vno < kMinKvno && k2.vno > kMaxKvno) {
            return TRUE;
        }
        if (!KerberosTSAfter(k1.timestamp, k2.timestamp) && k1.vno > kMaxKvno && k2.vno < kMinKvno) {
            return FALSE;
        }
        return k1.vno > k2.vno;
    }

    int32_t KerberosReadEntrySize(const KeytabValue &keytabValue, uint32_t &keypos, krb5_int32 &size) const
    {
        do {
            if (KerberosRead(keytabValue, &size, sizeof(size), 1, keypos) == 0) {
                return 1;
            }

            size = static_cast<krb5_int32>(ntohl(size));
            if (size < 0) {
                if (size == INT32_MIN) {
                    return 1;
                }
                keypos += static_cast<uint32_t>(-size);
                if (keypos > keytabValue.buf.size()) {
                    return errno;
                }
                continue;
            }
        } while (size < 0);

        return 0;
    }

    int32_t KerberosReadEntryPrincipalRealm(const KeytabValue &keytabValue, uint32_t &keypos,
                                            krb5_keytab_entry &retEntry) const
    {
        krb5_int16 princSize = 0;
        unsigned int uPrincSize;
        char *tmpdata = nullptr;

        if (KerberosRead(keytabValue, &princSize, sizeof(princSize), 1, keypos) == 0) {
            return 1;
        }
        princSize = static_cast<krb5_int16>(ntohs(princSize));
        if (princSize <= 0) {
            return 1;
        }
        uPrincSize = static_cast<unsigned int>(princSize);
        retEntry.principal->realm.length = uPrincSize;
        tmpdata = static_cast<char *>(malloc(uPrincSize + 1));
        if (tmpdata == nullptr) {
            return 1;
        }

        if (KerberosRead(keytabValue, tmpdata, 1, uPrincSize, keypos) == 0) {
            free(tmpdata);
            tmpdata = nullptr;
            return 1;
        }
        tmpdata[princSize] = 0;
        retEntry.principal->realm.data = tmpdata;

        return 0;
    }

    int32_t KerberosReadEntryPrincipalData(const KeytabValue &keytabValue, int32_t index, uint32_t &keypos,
                                           krb5_keytab_entry &retEntry) const
    {
        krb5_int16 princSize = 0;
        char *tmpdata = nullptr;
        unsigned int uPrincSize;

        krb5_data *princ = &retEntry.principal->data[index];
        if (princ == nullptr) {
            return 1;
        }
        if (KerberosRead(keytabValue, &princSize, sizeof(princSize), 1, keypos) == 0) {
            return 1;
        }
        princSize = static_cast<krb5_int16>(ntohs(princSize));
        if (princSize <= 0) {
            return 1;
        }
        uPrincSize = static_cast<unsigned int>(princSize);
        princ->length = uPrincSize;
        tmpdata = static_cast<char *>(malloc(uPrincSize + 1));
        if (tmpdata == nullptr) {
            return 1;
        }
        if (KerberosRead(keytabValue, tmpdata, sizeof(char), uPrincSize, keypos) == 0) {
            free(tmpdata);
            tmpdata = nullptr;
            return 1;
        }
        tmpdata[princSize] = 0;
        princ->data = tmpdata;

        return 0;
    }

    int32_t KerberosReadEntryPrincipal(const KeytabValue &keytabValue, uint32_t &keypos,
                                       krb5_keytab_entry &retEntry) const
    {
        int32_t error;
        krb5_int16 count = 0;
        unsigned int uCount;

        if (KerberosRead(keytabValue, &count, sizeof(count), 1, keypos) == 0) {
            return 1;
        }
        count = static_cast<krb5_int16>(ntohs(count));
        if (count <= 0) {
            return 1;
        }

        retEntry.principal = static_cast<krb5_principal>(calloc(1, sizeof(krb5_principal_data)));
        if (retEntry.principal == nullptr) {
            return 1;
        }

        uCount = static_cast<unsigned int>(count);
        retEntry.principal->magic = KV5M_PRINCIPAL;
        retEntry.principal->length = static_cast<uint16_t>(uCount);
        retEntry.principal->data = static_cast<krb5_data *>(calloc(uCount, sizeof(krb5_data)));
        if (retEntry.principal->data == nullptr) {
            return 1;
        }

        error = KerberosReadEntryPrincipalRealm(keytabValue, keypos, retEntry);
        if (error != 0) {
            return 1;
        }

        for (int32_t i = 0; i < count; i++) {
            error = KerberosReadEntryPrincipalData(keytabValue, i, keypos, retEntry);
            if (error != 0) {
                return 1;
            }
        }

        if (KerberosRead(keytabValue, &retEntry.principal->type, sizeof(retEntry.principal->type), 1, keypos) == 0) {
            return 1;
        }
        retEntry.principal->type = static_cast<int>(ntohl(retEntry.principal->type));

        return 0;
    }

    int32_t KerberosReadEntryTSVNo(const KeytabValue &keytabValue, uint32_t &keypos, krb5_keytab_entry &retEntry) const
    {
        krb5_octet vno = 0;

        if (KerberosRead(keytabValue, &retEntry.timestamp, sizeof(retEntry.timestamp), 1, keypos) == 0) {
            return 1;
        }
        retEntry.timestamp = static_cast<int>(ntohl(retEntry.timestamp));

        if (KerberosRead(keytabValue, &vno, sizeof(vno), 1, keypos) == 0) {
            return 1;
        }
        retEntry.vno = static_cast<krb5_kvno>(vno);

        return 0;
    }

    int32_t KerberosReadEntryKey(const KeytabValue &keytabValue, uint32_t &keypos, krb5_keytab_entry &retEntry) const
    {
        krb5_int16 count = 0;
        unsigned int uCount;
        krb5_int16 enctype = 0;

        if (KerberosRead(keytabValue, &enctype, sizeof(enctype), 1, keypos) == 0) {
            return 1;
        }
        enctype = static_cast<krb5_int16>(ntohs(enctype));
        retEntry.key.enctype = static_cast<krb5_enctype>(enctype);

        retEntry.key.magic = KV5M_KEYBLOCK;
        if (KerberosRead(keytabValue, &count, sizeof(count), 1, keypos) == 0) {
            return 1;
        }
        count = static_cast<krb5_int16>(ntohs(count));
        if (count <= 0) {
            return 1;
        }
        uCount = static_cast<unsigned int>(count);
        retEntry.key.length = uCount;
        retEntry.key.contents = static_cast<krb5_octet *>(malloc(uCount));
        if (retEntry.key.contents == nullptr) {
            return 1;
        }

        if (KerberosRead(keytabValue, retEntry.key.contents, sizeof(krb5_octet), count, keypos) == 0) {
            return 1;
        }
        return 0;
    }

    int32_t KerberosReadEntryContent(const KeytabValue &keytabValue, uint32_t &keypos, krb5_keytab_entry &retEntry)
    {
        int32_t error;

        error = KerberosReadEntryPrincipal(keytabValue, keypos, retEntry);
        if (error != 0) {
            return 1;
        }

        error = KerberosReadEntryTSVNo(keytabValue, keypos, retEntry);
        if (error != 0) {
            return 1;
        }

        error = KerberosReadEntryKey(keytabValue, keypos, retEntry);
        if (error != 0) {
            return 1;
        }

        return 0;
    }

    int32_t KerberosFreeEntryPrincipalData(krb5_keytab_entry &retEntry) const
    {
        for (int i = 0; i < retEntry.principal->length; i++) {
            if (retEntry.principal->data[i].data != nullptr) {
                free(retEntry.principal->data[i].data);
                retEntry.principal->data[i].data = nullptr;
            }
        }
        free(retEntry.principal->data);
        retEntry.principal->data = nullptr;
        return 0;
    }

    int32_t KerberosFreeEntry(krb5_keytab_entry &retEntry) const
    {
        if (retEntry.principal != nullptr) {
            if (retEntry.principal->data != nullptr) {
                (void)KerberosFreeEntryPrincipalData(retEntry);
            }
            free(retEntry.principal);
            retEntry.principal = nullptr;
        }
        if (retEntry.key.contents != nullptr) {
            free(retEntry.key.contents);
            retEntry.key.contents = nullptr;
        }
        return 0;
    }

    int32_t KerberosReadEntry(const KeytabValue &keytabValue, uint32_t &keypos, krb5_keytab_entry &retEntry)
    {
        krb5_int32 size = 0;
        uint32_t startPos;
        uint32_t endPos;
        int32_t error;
        uint32_t vno32 = 0;

        memset_s(&retEntry, sizeof(krb5_keytab_entry), 0, sizeof(krb5_keytab_entry));
        retEntry.magic = KV5M_KEYTAB_ENTRY;

        error = KerberosReadEntrySize(keytabValue, keypos, size);
        if ((error != 0) || (size <= 0)) {
            return 1;
        }

        startPos = keypos;

        error = KerberosReadEntryContent(keytabValue, keypos, retEntry);
        if ((error != 0) || (size == 0)) {
            (void)KerberosFreeEntry(retEntry);
            return 1;
        }

        endPos = keypos;

        if (endPos + sizeof(vno32) <= static_cast<uint32_t>(size) + startPos) {
            if (KerberosRead(keytabValue, &vno32, sizeof(vno32), 1, keypos) == 0) {
                (void)KerberosFreeEntry(retEntry);
                return 1;
            }
            vno32 = ntohl(vno32);
            if (vno32 != 0) {
                retEntry.vno = vno32;
            }
        }

        if (keypos > startPos + static_cast<uint32_t>(size)) {
            (void)KerberosFreeEntry(retEntry);
            return 1;
        }
        keypos = startPos + static_cast<uint32_t>(size);

        return 0;
    }

    uint32_t KerberosCompareEntry(krb5_kvno kvno, krb5_keytab_entry &curEntry, krb5_keytab_entry &newEntry,
                                  uint32_t &find)
    {
        if (kvno == 0 || newEntry.vno == 0) {
            if (curEntry.principal == nullptr || (KerberosMoreRecent(newEntry, curEntry) != 0U)) {
                Krb5Wrapper::krb5_kt_free_entry(krb5Context_, &curEntry);
                curEntry = newEntry;
                find = 1;
            } else {
                Krb5Wrapper::krb5_kt_free_entry(krb5Context_, &newEntry);
            }
        } else {
            if (newEntry.vno == kvno) {
                Krb5Wrapper::krb5_kt_free_entry(krb5Context_, &curEntry);
                curEntry = newEntry;
                find = 1;
                return 0;
            } else if (newEntry.vno == (kvno & 0xff) && curEntry.principal == nullptr) {
                curEntry = newEntry;
                find = 1;
            } else {
                Krb5Wrapper::krb5_kt_free_entry(krb5Context_, &newEntry);
            }
        }
        return 1;
    }

    KrbResult KerberosInit(const std::string &inPrincipal)
    {
        if (Krb5Wrapper::krb5_init_context(&krb5Context_) != 0) {
            (void)KerberosUninit();
            return {1, "krb5_init_context failed"};
        }
        if (Krb5Wrapper::krb5_parse_name(krb5Context_, inPrincipal.c_str(), &principal_) != 0) {
            (void)KerberosUninit();
            return {1, "krb5_parse_name could not parse principal"};
        }

        return {0, "KerberosInit Succeed"};
    }

    KrbResult KerberosGetEntry(const KeytabValue &keytabValue, krb5_kvno kvno, krb5_enctype enctype,
                               krb5_keytab_entry &entry)
    {
        krb5_keytab_entry curEntry;
        krb5_keytab_entry newEntry;
        uint16_t ktVNo = 0;
        uint32_t pos = 0;
        uint32_t find = 0;

        // Step 1: read ktVNO
        if (KerberosRead(keytabValue, &ktVNo, sizeof(ktVNo), 1, pos) == 0) {
            return {1, "read ktVNo error"};
        }
        ktVNo = ntohs(ktVNo);
        curEntry.principal = nullptr;
        curEntry.vno = 0;
        curEntry.key.contents = nullptr;

        // Step 2: recursively read all entries
        while (true) {
            if (KerberosReadEntry(keytabValue, pos, newEntry) != 0) {
                // in case of error, break
                break;
            }
            if ((Krb5Wrapper::krb5_principal_compare(krb5Context_, principal_, newEntry.principal) == 0U) ||
                (enctype != 0 && enctype != newEntry.key.enctype)) {
                Krb5Wrapper::krb5_kt_free_entry(krb5Context_, &newEntry);
                continue;
            }
            uint32_t flag = KerberosCompareEntry(kvno, curEntry, newEntry, find);
            if (flag == 0) {
                break;
            }
        }
        entry = curEntry;
        return find != 0 ? KrbResult(0, "GetEntry succeed") : KrbResult(1, "GetEntry Failed");
    }
};

// ---------------------
// PIMP Function Parsing
// ---------------------
KrbCtx::KrbCtx() : impl_(std::make_unique<KrbCtx::Impl>())
{}

KrbCtx::~KrbCtx() = default;

KrbResult KrbCtx::KerberosInitKeytab(const KeytabValue &keytabValue, const std::string &inPrincipal,
                                     const std::string &memoryKeytabName)
{
    return impl_->KerberosInitKeytab(keytabValue, inPrincipal, memoryKeytabName);
}

KrbResult KrbCtx::KerberosInitCCache(const KeytabValue &keytabValue, const std::string &inPrincipal,
                                     const std::string &memoryKeytabName, const std::string &inkrb5ccname)
{
    return impl_->KerberosInitCCache(keytabValue, inPrincipal, memoryKeytabName, inkrb5ccname);
}

KrbResult KrbCtx::KerberosDestroyKeytab()
{
    return impl_->KerberosDestroyKeytab();
}
KrbResult KrbCtx::KerberosDestroyCCache()
{
    return impl_->KerberosDestroyCCache();
}
KrbResult KrbCtx::KerberosUninit()
{
    return impl_->KerberosUninit();
}

} // namespace cdf
