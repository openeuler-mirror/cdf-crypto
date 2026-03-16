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

#include <dlfcn.h>

#include <atomic>
#include <sstream>
#include <string>

#include "gssapi/gssapi.h"
#include "gssapi/gssapi_krb5.h"
#include "krb5/krb5.h"

namespace cdf {

class Krb5Wrapper {
public:
#define CCSEC_DECLARE_KRB5_ALIAS(FUNC, ALIAS, RET_TYPE, ...) using ALIAS = RET_TYPE (*)(__VA_ARGS__)

    CCSEC_DECLARE_KRB5_ALIAS(krb5_init_context, Krb5InitContext, krb5_error_code, krb5_context *context);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_parse_name, Krb5ParseName, krb5_error_code, krb5_context context, const char *name,
                             krb5_principal *principalOut);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_free_principal, Krb5FreePrincipal, void, krb5_context, krb5_principal);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_free_context, Krb5FreeContext, void KRB5_CALLCONV, krb5_context context);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_principal_compare, Krb5PrincipalCompare, krb5_boolean KRB5_CALLCONV,
                             krb5_context context, krb5_const_principal princ1, krb5_const_principal princ2);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_kt_free_entry, Krb5KTFreeEntry, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             krb5_keytab_entry *entry);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_kt_resolve, Krb5KTResolve, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             const char *name, krb5_keytab *ktid);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_cc_default, Krb5CCDefault, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             krb5_ccache *ccache);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_cc_resolve, Krb5CCResolve, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             const char *name, krb5_ccache *ccache);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_kt_add_entry, Krb5KTAddEntry, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             krb5_keytab id, krb5_keytab_entry *entry);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_get_init_creds_opt_alloc, Krb5GetInitCredsOptAlloc, krb5_error_code KRB5_CALLCONV,
                             krb5_context context, krb5_get_init_creds_opt **opt);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_get_init_creds_keytab, Krb5GetInitCredsKeytab, krb5_error_code KRB5_CALLCONV,
                             krb5_context context, krb5_creds *creds, krb5_principal client, krb5_keytab argKeytab,
                             krb5_deltat startTime, const char *inTktService, krb5_get_init_creds_opt *k5GicOptions);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_cc_initialize, Krb5CCInitialize, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             krb5_ccache cache, krb5_principal principal);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_cc_store_cred, Krb5CCStoreCred, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             krb5_ccache cache, krb5_creds *creds);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_free_cred_contents, Krb5FreeCredContents, void KRB5_CALLCONV, krb5_context context,
                             krb5_creds *val);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_kt_close, Krb5KTClose, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             krb5_keytab keytab);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_cc_destroy, Krb5CCDestroy, krb5_error_code KRB5_CALLCONV, krb5_context context,
                             krb5_ccache cache);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_kt_remove_entry, Krb5KTRemoveEntry, krb5_error_code KRB5_CALLCONV,
                             krb5_context context, krb5_keytab id, krb5_keytab_entry *entry);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_get_init_creds_opt_free, Krb5GetInitCredsOptFree, void KRB5_CALLCONV,
                             krb5_context context, krb5_get_init_creds_opt *opt);
    CCSEC_DECLARE_KRB5_ALIAS(gss_inquire_context, GssInquireContext, OM_uint32 KRB5_CALLCONV, OM_uint32 *, gss_ctx_id_t,
                             gss_name_t *, gss_name_t *, OM_uint32 *, gss_OID *, OM_uint32 *, int *, int *);
    CCSEC_DECLARE_KRB5_ALIAS(gss_display_name, GssDisplayName, OM_uint32 KRB5_CALLCONV, OM_uint32 *, gss_name_t,
                             gss_buffer_t, gss_OID *);
    CCSEC_DECLARE_KRB5_ALIAS(gss_release_buffer, GssReleaseBuffer, OM_uint32 KRB5_CALLCONV, OM_uint32 *, gss_buffer_t);
    CCSEC_DECLARE_KRB5_ALIAS(gss_accept_sec_context, GssAcceptSecContext, OM_uint32 KRB5_CALLCONV, OM_uint32 *,
                             gss_ctx_id_t *, gss_cred_id_t, gss_buffer_t, gss_channel_bindings_t, gss_name_t *,
                             gss_OID *, gss_buffer_t, OM_uint32 *, OM_uint32 *, gss_cred_id_t *);
    CCSEC_DECLARE_KRB5_ALIAS(gss_delete_sec_context, GssDeleteSecContext, OM_uint32 KRB5_CALLCONV, OM_uint32 *,
                             gss_ctx_id_t *, gss_buffer_t);
    CCSEC_DECLARE_KRB5_ALIAS(gss_import_name, GssImportName, OM_uint32 KRB5_CALLCONV, OM_uint32 *, gss_buffer_t,
                             gss_OID, gss_name_t *);
    CCSEC_DECLARE_KRB5_ALIAS(gss_acquire_cred, GssAcquireCred, OM_uint32 KRB5_CALLCONV, OM_uint32 *, gss_name_t,
                             OM_uint32, gss_OID_set, gss_cred_usage_t, gss_cred_id_t *, gss_OID_set *, OM_uint32 *);
    CCSEC_DECLARE_KRB5_ALIAS(gss_init_sec_context, GssInitSecContext, OM_uint32 KRB5_CALLCONV, OM_uint32 *,
                             gss_cred_id_t, gss_ctx_id_t *, gss_name_t, gss_OID, OM_uint32, OM_uint32,
                             gss_channel_bindings_t, gss_buffer_t, gss_OID *, gss_buffer_t, OM_uint32 *, OM_uint32 *);
    CCSEC_DECLARE_KRB5_ALIAS(gss_release_name, GssReleaseName, OM_uint32 KRB5_CALLCONV, OM_uint32 *, gss_name_t *);
    CCSEC_DECLARE_KRB5_ALIAS(gss_release_cred, GssReleaseCred, OM_uint32 KRB5_CALLCONV, OM_uint32 *, gss_cred_id_t *);
    CCSEC_DECLARE_KRB5_ALIAS(krb5_free_keytab_entry_contents, Krb5FreeKeytabEntryContents,
                             krb5_error_code KRB5_CALLCONV, krb5_context, krb5_keytab_entry *);

    static Krb5FreeKeytabEntryContents krb5_free_keytab_entry_contents;
    static Krb5InitContext krb5_init_context;
    static Krb5ParseName krb5_parse_name;
    static Krb5FreePrincipal krb5_free_principal;
    static Krb5FreeContext krb5_free_context;
    static Krb5PrincipalCompare krb5_principal_compare;
    static Krb5KTFreeEntry krb5_kt_free_entry;
    static Krb5KTResolve krb5_kt_resolve;
    static Krb5CCDefault krb5_cc_default;
    static Krb5CCResolve krb5_cc_resolve;
    static Krb5KTAddEntry krb5_kt_add_entry;
    static Krb5GetInitCredsOptAlloc krb5_get_init_creds_opt_alloc;
    static Krb5GetInitCredsKeytab krb5_get_init_creds_keytab;
    static Krb5CCInitialize krb5_cc_initialize;
    static Krb5CCStoreCred krb5_cc_store_cred;
    static Krb5FreeCredContents krb5_free_cred_contents;
    static Krb5KTClose krb5_kt_close;
    static Krb5CCDestroy krb5_cc_destroy;
    static Krb5KTRemoveEntry krb5_kt_remove_entry;
    static Krb5GetInitCredsOptFree krb5_get_init_creds_opt_free;
    static GssInquireContext gss_inquire_context;
    static GssDisplayName gss_display_name;
    static GssReleaseBuffer gss_release_buffer;
    static GssAcceptSecContext gss_accept_sec_context;
    static GssDeleteSecContext gss_delete_sec_context;
    static GssImportName gss_import_name;
    static GssAcquireCred gss_acquire_cred;
    static GssInitSecContext gss_init_sec_context;
    static GssReleaseName gss_release_name;
    static GssReleaseCred gss_release_cred;
#undef CCSEC_DECLARE_KRB5_ALIAS
};
} // namespace cdf
