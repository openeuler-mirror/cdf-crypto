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

#ifndef CDF_OSSL_WRAPPERS_H
#define CDF_OSSL_WRAPPERS_H

#include <memory>
#include <string>

#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/core.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/decoder.h"
#include "openssl/ec.h"
#include "openssl/encoder.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/provider.h"

namespace cdf::ossl {
namespace internal {
// cpp-17+
template <auto DeleteFn> struct FunctionDeleter {
    template <class T> void operator()(T *ptr)
    {
        DeleteFn(ptr);
    }
};
template <class T, auto DeleteFn>
using TyHelper = std::unique_ptr<T, FunctionDeleter<DeleteFn>>;
};

/* message digests */
using UniqueMd = internal::TyHelper<EVP_MD, EVP_MD_free>;
using UniqueMdCtx = internal::TyHelper<EVP_MD_CTX, EVP_MD_CTX_free>;

/* block ciphers */
using UniqueCipher = internal::TyHelper<EVP_CIPHER, EVP_CIPHER_free>;
using UniqueCipherCtx = internal::TyHelper<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

// ------------------
// OpenSSL EVP Enum
// ------------------
inline UniqueMd FetchEvpMd(const std::string& md_str)
{
    return UniqueMd(EVP_MD_fetch(nullptr, md_str.c_str(), nullptr));
}

inline UniqueCipher FetchEvpCipher(const std::string& cipher_str)
{
    return UniqueCipher(EVP_CIPHER_fetch(nullptr, cipher_str.c_str(), nullptr));
}

inline std::string GetOSSLErr()
{
    BIO* bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char* buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}
}


#endif // CDF_OSSL_WRAPPERS_H
