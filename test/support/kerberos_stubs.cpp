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

#include "kerberos_stubs.h"

#include <algorithm>
#include <cstdlib>
#include <cstdint>

namespace cdf::test {
namespace {

thread_local KerberosStubState *g_state = nullptr;

KerberosStubState &ActiveState()
{
    return *g_state;
}

template<typename T>
T Sentinel(uintptr_t value)
{
    return reinterpret_cast<T>(value);
}

void ClearKeytabEntry(krb5_keytab_entry *entry)
{
    if (entry == nullptr) {
        return;
    }
    if (entry->principal != nullptr) {
        free(entry->principal->realm.data);
        for (int index = 0; index < entry->principal->length; ++index) {
            free(entry->principal->data[index].data);
        }
        free(entry->principal->data);
        free(entry->principal);
        entry->principal = nullptr;
    }
    free(entry->key.contents);
    entry->key.contents = nullptr;
}

void AppendU16(std::string &output, uint16_t value)
{
    output.push_back(static_cast<char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<char>(value & 0xffU));
}

void AppendU32(std::string &output, uint32_t value)
{
    output.push_back(static_cast<char>((value >> 24U) & 0xffU));
    output.push_back(static_cast<char>((value >> 16U) & 0xffU));
    output.push_back(static_cast<char>((value >> 8U) & 0xffU));
    output.push_back(static_cast<char>(value & 0xffU));
}

krb5_error_code StubInitContext(krb5_context *context)
{
    auto &state = ActiveState();
    ++state.initContextCalls;
    if (state.initContextRc == 0 && context != nullptr) {
        *context = Sentinel<krb5_context>(0x101);
    }
    return state.initContextRc;
}

krb5_error_code StubParseName(krb5_context, const char *, krb5_principal *principal)
{
    auto &state = ActiveState();
    ++state.parseNameCalls;
    if (state.parseNameRc == 0 && principal != nullptr) {
        *principal = Sentinel<krb5_principal>(0x102);
    }
    return state.parseNameRc;
}

void StubFreePrincipal(krb5_context, krb5_principal)
{
    ++ActiveState().freePrincipalCalls;
}

void StubFreeContext(krb5_context)
{
    ++ActiveState().freeContextCalls;
}

krb5_boolean StubPrincipalCompare(krb5_context, krb5_const_principal, krb5_const_principal)
{
    auto &state = ActiveState();
    ++state.principalCompareCalls;
    return state.principalCompare;
}

krb5_error_code StubFreeKeytabEntry(krb5_context, krb5_keytab_entry *entry)
{
    ++ActiveState().freeKeytabEntryCalls;
    ClearKeytabEntry(entry);
    return 0;
}

krb5_error_code StubResolveKeytab(krb5_context, const char *, krb5_keytab *keytab)
{
    auto &state = ActiveState();
    ++state.resolveKeytabCalls;
    if (state.resolveKeytabRc == 0 && keytab != nullptr) {
        *keytab = Sentinel<krb5_keytab>(0x103);
    }
    return state.resolveKeytabRc;
}

krb5_error_code StubDefaultCache(krb5_context, krb5_ccache *cache)
{
    auto &state = ActiveState();
    ++state.defaultCacheCalls;
    if (state.defaultCacheRc == 0 && cache != nullptr) {
        *cache = Sentinel<krb5_ccache>(0x104);
    }
    return state.defaultCacheRc;
}

krb5_error_code StubResolveCache(krb5_context, const char *, krb5_ccache *cache)
{
    auto &state = ActiveState();
    ++state.resolveCacheCalls;
    if (state.resolveCacheRc == 0 && cache != nullptr) {
        *cache = Sentinel<krb5_ccache>(0x104);
    }
    return state.resolveCacheRc;
}

krb5_error_code StubAddKeytabEntry(krb5_context, krb5_keytab, krb5_keytab_entry *)
{
    auto &state = ActiveState();
    ++state.addKeytabEntryCalls;
    return state.addKeytabEntryRc;
}

krb5_error_code StubAllocOptions(krb5_context, krb5_get_init_creds_opt **options)
{
    auto &state = ActiveState();
    ++state.allocOptionsCalls;
    if (state.allocOptionsRc == 0 && options != nullptr) {
        *options = Sentinel<krb5_get_init_creds_opt *>(0x105);
    }
    return state.allocOptionsRc;
}

krb5_error_code StubGetCredentials(krb5_context, krb5_creds *, krb5_principal, krb5_keytab, krb5_deltat,
                                  const char *, krb5_get_init_creds_opt *)
{
    auto &state = ActiveState();
    ++state.getCredentialsCalls;
    return state.getCredentialsRc;
}

krb5_error_code StubInitializeCache(krb5_context, krb5_ccache, krb5_principal)
{
    auto &state = ActiveState();
    ++state.initializeCacheCalls;
    return state.initializeCacheRc;
}

krb5_error_code StubStoreCredentials(krb5_context, krb5_ccache, krb5_creds *)
{
    auto &state = ActiveState();
    ++state.storeCredentialsCalls;
    return state.storeCredentialsRc;
}

void StubFreeCredentialContents(krb5_context, krb5_creds *)
{
    ++ActiveState().freeCredentialContentsCalls;
}

krb5_error_code StubCloseKeytab(krb5_context, krb5_keytab)
{
    ++ActiveState().closeKeytabCalls;
    return 0;
}

krb5_error_code StubDestroyCache(krb5_context, krb5_ccache)
{
    ++ActiveState().destroyCacheCalls;
    return 0;
}

krb5_error_code StubRemoveKeytabEntry(krb5_context, krb5_keytab, krb5_keytab_entry *)
{
    ++ActiveState().removeKeytabEntryCalls;
    return 0;
}

void StubFreeOptions(krb5_context, krb5_get_init_creds_opt *)
{
    ++ActiveState().freeOptionsCalls;
}

OM_uint32 StubInquireContext(OM_uint32 *minor, gss_ctx_id_t, gss_name_t *source, gss_name_t *target,
                             OM_uint32 *lifetime, gss_OID *mechanism, OM_uint32 *flags, int *local, int *open)
{
    auto &state = ActiveState();
    ++state.inquireContextCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if (source != nullptr) {
        *source = Sentinel<gss_name_t>(0x201);
    }
    if (target != nullptr) {
        *target = Sentinel<gss_name_t>(0x202);
    }
    if (lifetime != nullptr) {
        *lifetime = GSS_C_INDEFINITE;
    }
    if (mechanism != nullptr) {
        *mechanism = GSS_C_NO_OID;
    }
    if (flags != nullptr) {
        *flags = 0;
    }
    if (local != nullptr) {
        *local = 1;
    }
    if (open != nullptr) {
        *open = 1;
    }
    return state.gssInquireContextMajor;
}

OM_uint32 StubDisplayName(OM_uint32 *minor, gss_name_t, gss_buffer_t output, gss_OID *)
{
    auto &state = ActiveState();
    ++state.displayNameCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if (output != nullptr) {
        output->length = state.displayName.size();
        output->value = state.displayName.data();
    }
    return state.gssDisplayNameMajor;
}

OM_uint32 StubReleaseBuffer(OM_uint32 *minor, gss_buffer_t buffer)
{
    ++ActiveState().releaseBufferCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if (buffer != nullptr) {
        buffer->length = 0;
        buffer->value = nullptr;
    }
    return GSS_S_COMPLETE;
}

void SetOutputToken(KerberosStubState &state, gss_buffer_t output)
{
    if (output != nullptr) {
        output->length = state.outputToken.size();
        output->value = state.outputToken.empty() ? nullptr : state.outputToken.data();
    }
}

OM_uint32 StubAcceptContext(OM_uint32 *minor, gss_ctx_id_t *context, gss_cred_id_t, gss_buffer_t,
                            gss_channel_bindings_t, gss_name_t *source, gss_OID *, gss_buffer_t output,
                            OM_uint32 *, OM_uint32 *, gss_cred_id_t *)
{
    auto &state = ActiveState();
    ++state.acceptContextCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if ((state.gssAcceptContextMajor == GSS_S_COMPLETE || state.gssAcceptContextMajor == GSS_S_CONTINUE_NEEDED) &&
        context != nullptr) {
        *context = Sentinel<gss_ctx_id_t>(0x203);
    }
    if (source != nullptr) {
        *source = Sentinel<gss_name_t>(0x201);
    }
    if (state.gssAcceptContextMajor == GSS_S_COMPLETE || state.gssAcceptContextMajor == GSS_S_CONTINUE_NEEDED) {
        SetOutputToken(state, output);
    }
    return state.gssAcceptContextMajor;
}

OM_uint32 StubDeleteContext(OM_uint32 *minor, gss_ctx_id_t *context, gss_buffer_t)
{
    ++ActiveState().deleteContextCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if (context != nullptr) {
        *context = GSS_C_NO_CONTEXT;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 StubImportName(OM_uint32 *minor, gss_buffer_t, gss_OID, gss_name_t *name)
{
    auto &state = ActiveState();
    ++state.importNameCalls;
    OM_uint32 result = state.gssImportNameMajor;
    if (state.failImportNameOnCall > 0 && state.importNameCalls != state.failImportNameOnCall) {
        result = GSS_S_COMPLETE;
    }
    if (minor != nullptr) {
        *minor = 0;
    }
    if (result == GSS_S_COMPLETE && name != nullptr) {
        *name = Sentinel<gss_name_t>(0x201);
    }
    return result;
}

OM_uint32 StubAcquireCredential(OM_uint32 *minor, gss_name_t, OM_uint32, gss_OID_set, gss_cred_usage_t,
                                gss_cred_id_t *credential, gss_OID_set *, OM_uint32 *)
{
    auto &state = ActiveState();
    ++state.acquireCredentialCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if (state.gssAcquireCredMajor == GSS_S_COMPLETE && credential != nullptr) {
        *credential = Sentinel<gss_cred_id_t>(0x204);
    }
    return state.gssAcquireCredMajor;
}

OM_uint32 StubInitSecurityContext(OM_uint32 *minor, gss_cred_id_t, gss_ctx_id_t *context, gss_name_t, gss_OID,
                                  OM_uint32, OM_uint32, gss_channel_bindings_t, gss_buffer_t, gss_OID *,
                                  gss_buffer_t output, OM_uint32 *, OM_uint32 *)
{
    auto &state = ActiveState();
    ++state.initSecurityContextCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if ((state.gssInitContextMajor == GSS_S_COMPLETE || state.gssInitContextMajor == GSS_S_CONTINUE_NEEDED) &&
        context != nullptr) {
        *context = Sentinel<gss_ctx_id_t>(0x203);
    }
    if (state.gssInitContextMajor == GSS_S_COMPLETE || state.gssInitContextMajor == GSS_S_CONTINUE_NEEDED) {
        SetOutputToken(state, output);
    }
    return state.gssInitContextMajor;
}

OM_uint32 StubReleaseName(OM_uint32 *minor, gss_name_t *name)
{
    ++ActiveState().releaseNameCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if (name != nullptr) {
        *name = GSS_C_NO_NAME;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 StubReleaseCredential(OM_uint32 *minor, gss_cred_id_t *credential)
{
    ++ActiveState().releaseCredentialCalls;
    if (minor != nullptr) {
        *minor = 0;
    }
    if (credential != nullptr) {
        *credential = GSS_C_NO_CREDENTIAL;
    }
    return GSS_S_COMPLETE;
}

krb5_error_code StubFreeKeytabEntryContents(krb5_context, krb5_keytab_entry *entry)
{
    ++ActiveState().freeKeytabEntryCalls;
    ClearKeytabEntry(entry);
    return 0;
}

} // namespace

KeytabValue MakeMinimalKeytab()
{
    std::string entry;
    AppendU16(entry, 1);
    AppendU16(entry, 11);
    entry += "EXAMPLE.COM";
    AppendU16(entry, 4);
    entry += "user";
    AppendU32(entry, 1);
    AppendU32(entry, 1);
    entry.push_back(1);
    AppendU16(entry, 17);
    AppendU16(entry, 4);
    entry.append("key!", 4);

    KeytabValue keytab;
    AppendU16(keytab.buf, 0x0502);
    AppendU32(keytab.buf, static_cast<uint32_t>(entry.size()));
    keytab.buf += entry;
    return keytab;
}

void KerberosStubState::Reset()
{
    *this = KerberosStubState{};
}

KerberosApiScope::KerberosApiScope() : previousState_(g_state)
{
    g_state = &state_;
    Replace(Krb5Wrapper::krb5_free_keytab_entry_contents, &StubFreeKeytabEntryContents);
    Replace(Krb5Wrapper::krb5_init_context, &StubInitContext);
    Replace(Krb5Wrapper::krb5_parse_name, &StubParseName);
    Replace(Krb5Wrapper::krb5_free_principal, &StubFreePrincipal);
    Replace(Krb5Wrapper::krb5_free_context, &StubFreeContext);
    Replace(Krb5Wrapper::krb5_principal_compare, &StubPrincipalCompare);
    Replace(Krb5Wrapper::krb5_kt_free_entry, &StubFreeKeytabEntry);
    Replace(Krb5Wrapper::krb5_kt_resolve, &StubResolveKeytab);
    Replace(Krb5Wrapper::krb5_cc_default, &StubDefaultCache);
    Replace(Krb5Wrapper::krb5_cc_resolve, &StubResolveCache);
    Replace(Krb5Wrapper::krb5_kt_add_entry, &StubAddKeytabEntry);
    Replace(Krb5Wrapper::krb5_get_init_creds_opt_alloc, &StubAllocOptions);
    Replace(Krb5Wrapper::krb5_get_init_creds_keytab, &StubGetCredentials);
    Replace(Krb5Wrapper::krb5_cc_initialize, &StubInitializeCache);
    Replace(Krb5Wrapper::krb5_cc_store_cred, &StubStoreCredentials);
    Replace(Krb5Wrapper::krb5_free_cred_contents, &StubFreeCredentialContents);
    Replace(Krb5Wrapper::krb5_kt_close, &StubCloseKeytab);
    Replace(Krb5Wrapper::krb5_cc_destroy, &StubDestroyCache);
    Replace(Krb5Wrapper::krb5_kt_remove_entry, &StubRemoveKeytabEntry);
    Replace(Krb5Wrapper::krb5_get_init_creds_opt_free, &StubFreeOptions);
    Replace(Krb5Wrapper::gss_inquire_context, &StubInquireContext);
    Replace(Krb5Wrapper::gss_display_name, &StubDisplayName);
    Replace(Krb5Wrapper::gss_release_buffer, &StubReleaseBuffer);
    Replace(Krb5Wrapper::gss_accept_sec_context, &StubAcceptContext);
    Replace(Krb5Wrapper::gss_delete_sec_context, &StubDeleteContext);
    Replace(Krb5Wrapper::gss_import_name, &StubImportName);
    Replace(Krb5Wrapper::gss_acquire_cred, &StubAcquireCredential);
    Replace(Krb5Wrapper::gss_init_sec_context, &StubInitSecurityContext);
    Replace(Krb5Wrapper::gss_release_name, &StubReleaseName);
    Replace(Krb5Wrapper::gss_release_cred, &StubReleaseCredential);
}

KerberosApiScope::~KerberosApiScope()
{
    for (auto it = restorers_.rbegin(); it != restorers_.rend(); ++it) {
        (*it)();
    }
    g_state = previousState_;
}

KerberosStubState &KerberosApiScope::State()
{
    return state_;
}

} // namespace cdf::test
