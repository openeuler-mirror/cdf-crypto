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

#include "cdf/connector/krb5_wrapper.h"

namespace cdf {

Krb5Wrapper::Krb5InitContext Krb5Wrapper::krb5_init_context = &::krb5_init_context;
Krb5Wrapper::Krb5ParseName Krb5Wrapper::krb5_parse_name = &::krb5_parse_name;
Krb5Wrapper::Krb5FreePrincipal Krb5Wrapper::krb5_free_principal = &::krb5_free_principal;
Krb5Wrapper::Krb5FreeContext Krb5Wrapper::krb5_free_context = &::krb5_free_context;
Krb5Wrapper::Krb5PrincipalCompare Krb5Wrapper::krb5_principal_compare = &::krb5_principal_compare;
Krb5Wrapper::Krb5KTFreeEntry Krb5Wrapper::krb5_kt_free_entry = &::krb5_kt_free_entry;
Krb5Wrapper::Krb5KTResolve Krb5Wrapper::krb5_kt_resolve = &::krb5_kt_resolve;
Krb5Wrapper::Krb5KTAddEntry Krb5Wrapper::krb5_kt_add_entry = &::krb5_kt_add_entry;
Krb5Wrapper::Krb5CCDefault Krb5Wrapper::krb5_cc_default = &::krb5_cc_default;
Krb5Wrapper::Krb5CCResolve Krb5Wrapper::krb5_cc_resolve = &::krb5_cc_resolve;
Krb5Wrapper::Krb5GetInitCredsOptAlloc Krb5Wrapper::krb5_get_init_creds_opt_alloc = &::krb5_get_init_creds_opt_alloc;
Krb5Wrapper::Krb5GetInitCredsKeytab Krb5Wrapper::krb5_get_init_creds_keytab = &::krb5_get_init_creds_keytab;
Krb5Wrapper::Krb5CCInitialize Krb5Wrapper::krb5_cc_initialize = &::krb5_cc_initialize;
Krb5Wrapper::Krb5CCStoreCred Krb5Wrapper::krb5_cc_store_cred = &::krb5_cc_store_cred;
Krb5Wrapper::Krb5FreeCredContents Krb5Wrapper::krb5_free_cred_contents = &::krb5_free_cred_contents;
Krb5Wrapper::Krb5KTClose Krb5Wrapper::krb5_kt_close = &::krb5_kt_close;
Krb5Wrapper::Krb5CCDestroy Krb5Wrapper::krb5_cc_destroy = &::krb5_cc_destroy;
Krb5Wrapper::Krb5KTRemoveEntry Krb5Wrapper::krb5_kt_remove_entry = &::krb5_kt_remove_entry;
Krb5Wrapper::Krb5GetInitCredsOptFree Krb5Wrapper::krb5_get_init_creds_opt_free = &::krb5_get_init_creds_opt_free;
Krb5Wrapper::GssInquireContext Krb5Wrapper::gss_inquire_context = &::gss_inquire_context;
Krb5Wrapper::GssDisplayName Krb5Wrapper::gss_display_name = &::gss_display_name;
Krb5Wrapper::GssReleaseBuffer Krb5Wrapper::gss_release_buffer = &::gss_release_buffer;
Krb5Wrapper::GssAcceptSecContext Krb5Wrapper::gss_accept_sec_context = &::gss_accept_sec_context;
Krb5Wrapper::GssDeleteSecContext Krb5Wrapper::gss_delete_sec_context = &::gss_delete_sec_context;
Krb5Wrapper::GssImportName Krb5Wrapper::gss_import_name = &::gss_import_name;
Krb5Wrapper::GssAcquireCred Krb5Wrapper::gss_acquire_cred = &::gss_acquire_cred;
Krb5Wrapper::GssInitSecContext Krb5Wrapper::gss_init_sec_context = &::gss_init_sec_context;
Krb5Wrapper::GssReleaseName Krb5Wrapper::gss_release_name = &::gss_release_name;
Krb5Wrapper::GssReleaseCred Krb5Wrapper::gss_release_cred = &::gss_release_cred;
Krb5Wrapper::Krb5FreeKeytabEntryContents Krb5Wrapper::krb5_free_keytab_entry_contents =
    &::krb5_free_keytab_entry_contents;

} // namespace cdf
