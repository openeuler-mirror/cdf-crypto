// Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
// Confidential Data defensive Framework is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#pragma once

namespace cdf {
typedef enum {
    CCSEC_CRYPT_OK = 0,                     // Success
    CCSEC_CRYPT_ERROR,                      // Failed
    CCSEC_CRYPT_PARAM_INVALID,              // The param is invalid
    CCSEC_CRYPT_PARAM_DOMAIN_COUNT_INVALID, // the domain count is invalid
    CCSEC_CRYPT_KMC_INIT_FAILED,            // Init kmc failed
    CCSEC_CRYPT_KEY_ACTIVE_FAILED,

    CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL,
    CCSEC_OPENSSL_CRYPT_NULL_INPUT = 0x01010001,              //  Null pointer input error, bufferLen is 0.
    CCSEC_OPENSSL_CRYPT_SECUREC_FAIL,                         // Security function  returns an error.
    CCSEC_OPENSSL_CRYPT_MEM_ALLOC_FAIL,                       // Failed to apply for memory.
    CCSEC_OPENSSL_CRYPT_NO_REGIST_RAND,                       // The global random number is not registered.
    CCSEC_OPENSSL_CRYPT_EAL_BUFF_LEN_NOT_ENOUGH = 0x01020001, //  Insufficient buffer length.
    CCSEC_OPENSSL_CRYPT_EAL_ERR_ALGID,                        // Incorrect algorithm ID.
    CCSEC_OPENSSL_CRYPT_EAL_ALG_NOT_SUPPORT,   // Algorithm not supported, algorithm behavior not supported.
    CCSEC_OPENSSL_CRYPT_EAL_ERR_NOT_REGISTER,  // Algorithm function is not registered.
    CCSEC_OPENSSL_CRYPT_EAL_CIPHER_CTRL_ERROR, //  CRYPT_EAL_CipherCtrl interface unsupported CTRL type.
    /* The usage process is incorrect. For example, run the update command without
    running the init command. For details, see related algorithms. */
    CCSEC_OPENSSL_CRYPT_EAL_ERR_STATE,
    CCSEC_OPENSSL_CRYPT_EAL_ERR_PART_OVERLAP,    // Some memory overlap.
    CCSEC_OPENSSL_CRYPT_EAL_ERR_RAND_NO_WORKING, // DRBG is not working.

    CCSEC_OPENSSL_CRYPT_EAL_ERR_GLOBAL_DRBG_NULL, // The global DRBG is null.

    CCSEC_OPENSSL_CRYPT_EAL_ERR_DRBG_REPEAT_INIT, // DRBG is initialized repeatedly.
    CCSEC_OPENSSL_CRYPT_EAL_ERR_DRBG_INIT_FAIL,   // DRBG initialization failure.

    CCSEC_OPENSSL_CRYPT_MODE_ERR_INPUT_LEN = 0x01030001, // The function input length is not the expected length.
    CCSEC_OPENSSL_CRYPT_AES_ERR_KEYLEN = 0x01040001,     // Incorrect key length.

    CCSEC_OPENSSL_CRYPT_CMVP_NOT_APPROVED = 0x01050001, // Does not meet the standard requirements.
    /* In ccm mode, When the ctrl interface is used to set the msg length, the input parameter length or the
    input parameter data length is incorrect. (This specification is affected by ivLen.) */
    CCSEC_OPENSSL_CRYPT_MODES_CTRL_MSGLEN_ERROR = 0x01100001,
    CCSEC_OPENSSL_CRYPT_PBKDF2_PARAM_ERROR = 0x01150001, // Incorrect input parameter.
    CCSEC_OPENSSL_CRYPT_PBKDF2_NOT_SUPPORTED             // Does not support the PBKDF2 algorithm.
} CcsecCryptErrorCode;
} // namespace cdf
