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

#include <cstdint>
#include <string>

#include "cdf/modules/authentication/jwt/define.h"
#include "cdf/modules/cryption/define.h"

namespace cdf {

struct CDFDistAuthServerOptions {
    /* keyTransferMode,
     * JwtAuthMode::INTERNAL_KEY means you use openbao encrypt the key, you should use
     * SetEncryptionKey provide the key and RefreshEncryptionKey refresh the key
     * and provide
     * params(openbaoExecPath,openbaoAccessToken,domainCount,domainId)
     * in this struct;
     *
     * JwtAuthMode::EXTERNAL_KEY means you provide the key and keyLen when create and
     * validate the token, you should provide the key and keyLen in
     * see@CDFDistAuthCreateTokenOptions and see@CDFDistAuthValidateTokenOptions
     */
    JwtAuthMode keyTransferMode = JwtAuthMode::INTERNAL_KEY;
    /* distribute token expire time, -1 means no expiration */
    int16_t tokenExpireMinutes = 480;
    /* algorithm for secure , enum in see@CryptoHmacAlg */
    CryptoHmacAlg algType = CryptoHmacAlg::HMAC_SHA256;
    /* km option, default openbao, enum in see@KeyManagerTy, flag equal to 0, you need provide this param */
    KeyManagerTy keyManagerType = KeyManagerTy::OPENBAO;
    /* server key expire time, -1 means no expiration, flag equal to 0, you need
     * provide this param */
    int16_t serverKeyExpiredHours = 24;
    /* domain count, flag equal to 0, you need provide this param */
    int16_t domainCount = 2;
    /* domain id, must in domain count, flag equal to 0, you need provide this param */
    int16_t domainId = 0;
    /* openbao executable path, path of the openbao binary executable file, eg: /usr/bin/bao,
     * flag equal to 0, you need provide this param */
    std::string execPath;
    /* openbao access token, path of the openbao binary executable file, flag equal to 0, you need provide this param */
    std::string accessToken;
};

struct CDFDistAuthCreateTokenOptions {
    /* [in] key for hmac, flag equal to 1, you need provide this param */
    const char *key = nullptr;
    /* [in] key length, contain the terminator "\0", flag equal to 1, you need
     * provide this param */
    uint32_t keyLen = 0;
    /* [in] the data you input to create the token */
    const char *input = nullptr;
    /* [in] input data length, contain the terminator "\0" */
    uint32_t inputLen = 0;
    /* [out] generated token  */
    char *token = nullptr;
    /* [in&out] Length of the token you applied for */
    uint32_t tokenLen = 0;
};

struct CDFDistAuthValidateTokenOptions {
    /* [in] key for hmac, flag equal to 1, you need provide this param */
    const char *key = nullptr;
    /* [in] key length, contain the terminator "\0", flag equal to 1, you need
     * provide this param */
    uint32_t keyLen = 0;
    /* [in] the token to be validated */
    const char *token = nullptr;
    /* [in] token length, contain the terminator "\0" */
    uint32_t tokenLen = 0;
};

} // namespace cdf
