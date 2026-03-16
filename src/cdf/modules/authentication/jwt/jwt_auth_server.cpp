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

#include "cdf/modules/authentication/jwt/jwt_auth_server.h"

#include <iterator>
#include <string>
#include <utility>
#include <vector>
#include <unistd.h>

#include "securec/securec.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"
#include "cdf/base/custom_logger.h"
#include "cdf/modules/authentication/jwt/define.h"
#include "cdf/modules/authentication/jwt/jwt_token.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/cryption/hmac.h"
#include "cdf/modules/cryption/km_cryptor.h"
#include "cdf/modules/key_management/define.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/utils/base64.h"
#include "cdf/utils/str_utils.h"
#include "cdf/utils/file_utils.h"

namespace cdf {

namespace {

const char *JWT_SEP_DOT = ".";

inline void TryFixBase64(const std::string &input, std::string &output)
{
    std::string inputStr = input;
    switch (inputStr.size() % NUM_4) {
        case 0:
            output = inputStr;
            break;
        case NUM_2:
            inputStr += "==";
            output = inputStr;
            break;
        case NUM_3:
            inputStr += "=";
            output = inputStr;
            break;
        default:
            CCSEC_LOG_ERROR("Illegal base64url String!");
    }
}

std::pair<JwtAuthRC, CryptoHmacAlg> GetAlgType(const std::vector<std::string> &algVec)
{
    int typeId = 0;
    if (!StrUtils::StrToInt(algVec[1], typeId)) {
        CCSEC_LOG_ERROR("|GetAlgType|returnF|Invalid string conversion, cannot convert str: "
                        << algVec[1] << " to int.");
        return {JwtAuthRC::PARAM_INVALID, CryptoHmacAlg::UNKNOWN};
    }

    if (CCSEC_UNLIKELY(!CryptoHmacAlgCheck::IsValue(typeId))) {
        CCSEC_LOG_ERROR("|GetAlgType|returnF|Invalid CryptoHmacAlg, int: " << typeId);
        return {JwtAuthRC::PARAM_INVALID, CryptoHmacAlg::UNKNOWN};
    } else {
        return {JwtAuthRC::OK, static_cast<CryptoHmacAlg>(typeId)};
    }
}
} // namespace

class JwtAuthServer::Impl {
public:
    JwtAuthRC Start(const CDFDistAuthServerOptions &opt)
    {
        std::lock_guard<std::mutex> guard(mMutex);
        if (started_) {
            return JwtAuthRC::OK;
        }

        if (opt.keyTransferMode != JwtAuthMode::INTERNAL_KEY && opt.keyTransferMode != JwtAuthMode::EXTERNAL_KEY) {
            CCSEC_LOG_ERROR("The flag is wrong, please use correct type.");
            return JwtAuthRC::PARAM_INVALID;
        }

        auto result = ValidateOptions(opt);
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }

        tokenHeader_ = JwtTokenHeader(options_.algType, options_.tokenExpireMinutes);

        if (options_.keyTransferMode == JwtAuthMode::INTERNAL_KEY) {
            CCSEC_LOG_INFO("opt.domainId: " << opt.domainId << ", opt.domainCount: " << opt.domainCount);
            auto *km = KeyManagerFactory::Borrow(options_.keyManagerType);
            if (km == nullptr) {
                CCSEC_LOG_ERROR("|JwtAuthServer::Impl::Start|returnF|borrow KeyManager failed.");
                return JwtAuthRC::ERROR;
            }
            auto rc = km->Init(options_.execPath, options_.accessToken, options_.domainCount);
            if (CCSEC_UNLIKELY(rc != KeyManagerRC::OK)) {
                CCSEC_LOG_ERROR("|JwtAuthServer::Impl::Start|returnF|Key manager init failed.");
                return JwtAuthRC::KEY_MANAGER_INIT_FAIL;
            }

            keyPass_ = JwtKeyPass(options_.serverKeyExpiredHours);
        }

        started_ = true;
        return (JwtAuthRC::OK);
    }

    JwtAuthRC Stop()
    {
        std::lock_guard<std::mutex> guard(mMutex);
        if (!started_) {
            return JwtAuthRC::OK;
        }
        started_ = false;
        if (options_.keyTransferMode == JwtAuthMode::INTERNAL_KEY) {
            auto *km = KeyManagerFactory::Borrow(options_.keyManagerType);
            if (km == nullptr) {
                CCSEC_LOG_ERROR("|JwtAuthServer::Impl::Stop|returnF|borrow KeyManager failed.");
                return JwtAuthRC::ERROR;
            }
            km->UnInit();
        }
        return JwtAuthRC::OK;
    }

    JwtAuthRC CheckKeyLen(const uint32_t keyLen)
    {
        JwtAuthRC ret = JwtAuthRC::OK;
        if (options_.algType == CryptoHmacAlg::HMAC_SHA256) {
            if (keyLen < HMAC_SHA256_MIN_LENGTH) {
                ret = JwtAuthRC::PARAM_INVALID;
            }
        } else if (options_.algType == CryptoHmacAlg::HMAC_SHA384) {
            if (keyLen < HMAC_SHA384_MIN_LENGTH) {
                ret = JwtAuthRC::PARAM_INVALID;
            }
        } else if (options_.algType == CryptoHmacAlg::HMAC_SHA512) {
            if (keyLen < HMAC_SHA512_MIN_LENGTH) {
                ret = JwtAuthRC::PARAM_INVALID;
            }
        } else {
            ret = JwtAuthRC::PARAM_INVALID;
        }
        return ret;
    }

    JwtAuthRC RefreshEncryptionKey(const char *newKey, uint32_t keyLen)
    {
        if (!started_) {
            CCSEC_LOG_ERROR("|RefreshEncryptionKey|END|returnF||JwtAuthServer is not started.");
            return JwtAuthRC::ERROR;
        }
        if (options_.keyTransferMode != JwtAuthMode::INTERNAL_KEY) {
            CCSEC_LOG_ERROR("|RefreshEncryptionKey|returnF|Unsupported key transferring configuration mode.");
            return JwtAuthRC::PARAM_INVALID;
        }
        if (CCSEC_UNLIKELY(newKey == nullptr || keyLen == 0)) {
            CCSEC_LOG_ERROR("|RefreshEncryptionKey|returnF|Failed to refresh encryption key, as input key is null.");
            return JwtAuthRC::PARAM_INVALID;
        }
        if (CCSEC_UNLIKELY(keyLen >= JWT_KEY_LENGTH_MAX)) {
            CCSEC_LOG_ERROR("|RefreshEncryptionKey|returnF|Failed to refresh encryption key, as key is too long.");
            return JwtAuthRC::PARAM_INVALID;
        }

        auto ret = CheckKeyLen(keyLen);
        if (ret != JwtAuthRC::OK) {
            CCSEC_LOG_ERROR("|RefreshEncryptionKey|returnF|Failed to check key Len, keyLen:" << keyLen);
            return JwtAuthRC::PARAM_INVALID;
        }
        auto rc = keyPass_.RefreshKey(newKey, keyLen, options_.keyManagerType, options_.domainId,
                                      JWT_DEFAULT_SYM_ENC_ALG);
        return rc;
    }

    JwtAuthRC SetEncryptionKey(const char *newKey, uint32_t keyLen)
    {
        if (!started_) {
            CCSEC_LOG_ERROR("|SetEncryptionKey|END|returnF||JwtAuthServer is not started.");
            return JwtAuthRC::ERROR;
        }
        if (options_.keyTransferMode != JwtAuthMode::INTERNAL_KEY) {
            CCSEC_LOG_ERROR("JwtAuthServer::Impl::SetEncryptionKey|returnF"
                            "|Unsupported key transferring configuration mode.");
            return JwtAuthRC::NOT_SUPPORTED;
        }
        if (CCSEC_UNLIKELY(newKey == nullptr || keyLen == 0)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::SetEncryptionKey|"
                            "returnF|Failed to set encryption key, as input key is null.");
            return JwtAuthRC::PARAM_INVALID;
        }
        if (CCSEC_UNLIKELY(keyLen >= JWT_KEY_LENGTH_MAX)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::SetEncryptionKey|"
                            "returnF|Failed to refresh encryption key, as key is too long.");
            return JwtAuthRC::PARAM_INVALID;
        }

        auto ret = CheckKeyLen(keyLen);
        if (ret != JwtAuthRC::OK) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::SetEncryptionKey|returnF|"
                            "Failed to check key Len, keyLen:" << keyLen);
            return JwtAuthRC::PARAM_INVALID;
        }
        if (strnlen(newKey, keyLen) != keyLen) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::SetEncryptionKey|returnF|Failed to set encryption key as key size "
                            "is invalid.");
            return JwtAuthRC::PARAM_INVALID;
        }
        auto rc =
            keyPass_.SetKey(newKey, keyLen, options_.keyManagerType, options_.domainId, JWT_DEFAULT_SYM_ENC_ALG);
        return rc;
    }

    JwtAuthRC EstimateTokenLength(uint32_t inputLen, uint32_t *outputLen)
    {
        if (outputLen == nullptr) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::EstimateTokenLength|returnF|Invalid outputlen (nullptr).");
            return JwtAuthRC::PARAM_INVALID;
        }

        if (inputLen > JWT_INPUT_LENGTH_MAX) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::EstimateTokenLength|returnF|Failed to create estimate token size, "
                            "input size is too long. current: " << inputLen << ", max: " << JWT_INPUT_LENGTH_MAX);
            return JwtAuthRC::PARAM_INVALID;
        }

        auto outLen = GetEstimateHmacOutLen(tokenHeader_.GetAlgTy());
        if (outLen == 0) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::EstimateTokenLength|returnF|GetEstimateHmacOutLen return 0");
            return JwtAuthRC::PARAM_INVALID;
        }
        *outputLen = Base64EncodeLen(tokenHeader_.ToString().size()) + Base64EncodeLen(inputLen) +
                     Base64EncodeLen(outLen) + NUM_2;

        return JwtAuthRC::OK;
    }

    JwtAuthRC CreateToken(CDFDistAuthCreateTokenOptions &options)
    {
        auto result = CheckCreateTokenParams(options);
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }
        std::vector<char> innerToken;

        switch (options_.keyTransferMode) {
            case JwtAuthMode::INTERNAL_KEY: {
                auto ret = CreateTokenFromInternalKey(options, innerToken);
                if (ret != JwtAuthRC::OK) {
                    return ret;
                }
                break;
            }
            case JwtAuthMode::EXTERNAL_KEY: {
                if (options.key == nullptr || options.keyLen == 0) {
                    CCSEC_LOG_ERROR("|JwtAuthServer::Impl::CreateToken|returnF|Key pass is null.");
                    return JwtAuthRC::KEY_PASS_INVALID;
                }

                if (strnlen(options.key, options.keyLen) != options.keyLen - 1) {
                    return JwtAuthRC::PARAM_INVALID;
                }
                if (CreateTokenFromExternalKey(options.key, options.keyLen, options.input, options.inputLen,
                                               innerToken) != JwtAuthRC::OK) {
                    return JwtAuthRC::CREATE_TOKEN_FAIL;
                }
                break;
            }
            default:
                CCSEC_LOG_ERROR("|JwtAuthServer::Impl::CreateToken|returnF|Unsupported JwtAuthMode: "
                                << (int)options_.keyTransferMode);
                return JwtAuthRC::PARAM_INVALID;
        }

        innerToken.push_back('\0'); // indicate the end

        if (options.tokenLen < innerToken.size()) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::CreateToken|returnF|Token size is too short.");
            return JwtAuthRC::CREATE_TOKEN_FAIL;
        }
        // size does not cound the extra '\0", make it same as str.size()
        options.tokenLen = innerToken.size() - 1;

        // mem does have the extra '\0", make it same as str.c_str()
        if (memcpy_s(options.token, options.tokenLen + 1, innerToken.data(), innerToken.size()) != EOK) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::CreateToken|returnF|memcpy_s error");
            return JwtAuthRC::ERROR;
        }

        return JwtAuthRC::OK;
    }

    JwtAuthRC ValidateToken(const CDFDistAuthValidateTokenOptions &options)
    {
        auto result = CheckValidateTokenParams(options);
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }

        auto b64Vec = StrUtils::Split(options.token, JWT_SEP_DOT);
        if (CCSEC_UNLIKELY(b64Vec.empty() || b64Vec.size() != NUM_3)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::ValidateToken|returnF|Spit token failed.");
            return JwtAuthRC::PARAM_INVALID;
        }

        // Check the token expired or not and get the alg type in token
        CryptoHmacAlg algType = CryptoHmacAlg::HMAC_SHA256;
        result = CheckTokenExpiredTime(b64Vec, algType);
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }

        std::string signB64;
        std::ostringstream totalB64oss;
        totalB64oss << b64Vec[0] << JWT_SEP_DOT << b64Vec[1];
        std::string totalB64Str = totalB64oss.str();

        if (CCSEC_UNLIKELY(options_.keyTransferMode == JwtAuthMode::INTERNAL_KEY)) {
            result = ValidateTokenFromInternalKey(algType, b64Vec, totalB64Str, signB64);
            if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
                return result;
            }
        } else {
            if (CCSEC_UNLIKELY(options.key == nullptr || options.keyLen == 0)) {
                CCSEC_LOG_ERROR("|JwtAuthServer::Impl::ValidateToken|returnF|Key pass is null.");
                return JwtAuthRC::KEY_PASS_INVALID;
            }
            if (strnlen(options.key, options.keyLen) != options.keyLen - 1) {
                CCSEC_LOG_ERROR("|JwtAuthServer::Impl::ValidateToken|returnF|Key size is invalid.");
                return JwtAuthRC::PARAM_INVALID;
            }
            result = CalSignB64(algType, totalB64Str, signB64, options.key, options.keyLen);
            if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
                return result;
            }
        }

        if (CCSEC_UNLIKELY(signB64 != b64Vec[NUM_2])) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::ValidateToken|returnF|Failed to validate token signature is not "
                            "match with both key pass and old key pass");
            return JwtAuthRC::TOKEN_VALIDATE_FAIL;
        }

        return JwtAuthRC::OK;
    }

private:
    static std::mutex mMutex;
    bool started_ = false;
    CDFDistAuthServerOptions options_{};
    std::string name_;

    JwtTokenHeader tokenHeader_;
    JwtKeyPass keyPass_;

    JwtAuthRC ValidateTokenFromInternalKey(CryptoHmacAlg algType, const std::vector<std::string> &b64Vec,
                                           std::string_view totalB64Str, std::string &signB64)
    {
        if (CCSEC_UNLIKELY((keyPass_.GetKey().empty() || keyPass_.IsExpired()) &&
                           (CCSEC_UNLIKELY(keyPass_.GetOldKey().empty()) || keyPass_.IsOldKeyExpired()))) {
            CCSEC_LOG_ERROR("Failed to validate token as new key paas and old key pass both null or expired.");
            return JwtAuthRC::KEY_PASS_INVALID;
        }

        auto result =
            CheckCalculateSignature(algType, keyPass_.GetKey().data(), keyPass_.GetKey().size(), totalB64Str, signB64);
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }

        if (CCSEC_UNLIKELY(signB64 != b64Vec[NUM_2])) {
            if (keyPass_.GetOldKey().empty() || keyPass_.IsOldKeyExpired()) {
                CCSEC_LOG_ERROR("Failed to validate token signature does not match with key pass");
                return JwtAuthRC::TOKEN_VALIDATE_FAIL;
            }

            result = CheckCalculateSignature(algType, keyPass_.GetOldKey().data(), keyPass_.GetOldKey().size(),
                                             totalB64Str, signB64);
            if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
                return result;
            }

            if (CCSEC_UNLIKELY(signB64 != b64Vec[NUM_2])) {
                CCSEC_LOG_ERROR(
                    "Failed to validate token signature does not match with both key pass and old key pass");
                return JwtAuthRC::TOKEN_VALIDATE_FAIL;
            }
        }

        return JwtAuthRC::OK;
    }

    JwtAuthRC ValidateOptions(const CDFDistAuthServerOptions &opt)
    {
        if (CCSEC_UNLIKELY(!CryptoHmacAlgCheck::IsValue(opt.algType))) {
            CCSEC_LOG_ERROR("|JwtServer::Impl::ValidateOptions|returnF|Invalid CryptoHmacAlgType: "
                            << (int)opt.algType);
            return JwtAuthRC::PARAM_INVALID;
        }

        if (opt.keyTransferMode != JwtAuthMode::EXTERNAL_KEY) {
            if (static_cast<uint32_t>(opt.domainCount) > DOMAIN_ID_MAX || opt.domainId < 0 ||
                opt.domainId >= opt.domainCount) {
                CCSEC_LOG_ERROR("|JwtServer::Impl::ValidateOptions|returnF|Invalid domain id or domain count: "
                                << opt.domainId << ", domain count is: " << opt.domainCount);
                return JwtAuthRC::PARAM_INVALID;
            }
            if (opt.tokenExpireMinutes < -1 || opt.tokenExpireMinutes > JWT_EXPIRE_TIME_MAX_MINUTE) {
                CCSEC_LOG_ERROR(
                    "|JwtServer::Impl::ValidateOptions|returnF|Invalid token expire miniutes: "
                    << opt.tokenExpireMinutes << ", max is: " << JWT_EXPIRE_TIME_MAX_MINUTE);
                return JwtAuthRC::PARAM_INVALID;
            }
            if (opt.serverKeyExpiredHours < -1 ||
                JWT_MINUTES_PER_HOUR * opt.serverKeyExpiredHours > JWT_EXPIRE_TIME_MAX_MINUTE) {
                CCSEC_LOG_ERROR("|JwtServer::Impl::ValidateOptions|returnF|Invalid server key expire time (in "
                                "minutes): " << JWT_MINUTES_PER_HOUR * opt.serverKeyExpiredHours << ", max is: "
                                << JWT_EXPIRE_TIME_MAX_MINUTE);
                return JwtAuthRC::PARAM_INVALID;
            }
            std::string execPathStr(opt.execPath);
            if (!FileUtils::CanonicalPath(execPathStr) || !FileUtils::CheckUserAccess(execPathStr, (R_OK | X_OK))) {
                CCSEC_LOG_ERROR("|JwtServer::Impl::ValidateOptions|returnF|Invalid bianry path,"
                                "or missing read & execute permission");
                return JwtAuthRC::PARAM_INVALID;
            }
            if (opt.accessToken.empty()) {
                CCSEC_LOG_ERROR("|JwtServer::Impl::ValidateOptions|END|returnF||accessToken is empty.");
                return JwtAuthRC::PARAM_INVALID;
            }
        }

        options_ = opt;
        return JwtAuthRC::OK;
    }

    JwtAuthRC CreateTokenFromInternalKey(const CDFDistAuthCreateTokenOptions &options, std::vector<char> &innerToken)
    {
        if (keyPass_.GetKey().empty() || keyPass_.IsExpired()) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::CreateTokenByKeyPass|Failed to create token as key pass is null or "
                            "expired, please set key before create token.");
            return JwtAuthRC::KEY_PASS_INVALID;
        }

        // Decrypt the key saved in the mKeypass
        auto [rc, plaintext] = KmCryptor(options_.keyManagerType)
                                   .Decrypt(JWT_DEFAULT_SYM_ENC_ALG, keyPass_.GetKey(), options_.domainId);
        if (rc != CryptionRC::OK) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::CreateTokenByKeyPass|Key manager decryption failed, rc:"
                            << (int)rc);
            return JwtAuthRC::DECRYPT_FAIL;
        }

        auto ret = CreateTokenFromExternalKey(reinterpret_cast<const char *>(plaintext.data()), plaintext.size(),
                                              options.input, options.inputLen, innerToken);
        if (ret != JwtAuthRC::OK) {
            (void)memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());
            return JwtAuthRC::CREATE_TOKEN_FAIL;
        }
        (void)memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());

        return JwtAuthRC::OK;
    }

    JwtAuthRC CreateTokenFromExternalKey(const char *key, uint32_t keyLen, const char *input, uint32_t inputLen,
                                         std::vector<char> &innerToken)
    {
        // step1: header base64 encoder
        std::string headStr = tokenHeader_.ToString();
        auto headerB64 = Base64Encode(headStr.c_str(), headStr.size());
        if (headerB64.empty()) {
            CCSEC_LOG_ERROR("CreateTokenFromExternalKey|END|returnF|base64 encode error.");
            return JwtAuthRC::BASE64_ENCODE_FAIL;
        }
        auto headerB64Str = StrUtils::Split(MakeStringView(headerB64), "=")[0];

        // step2: payload base64 encoder
        auto payloadB64 = Base64Encode(input, inputLen);

        // step3: calculate signature
        std::ostringstream totalB64Oss;
        totalB64Oss << headerB64Str << JWT_SEP_DOT << MakeStringView(payloadB64);
        std::string totalB64Str = totalB64Oss.str();
        std::vector<char> totalB64(totalB64Str.begin(), totalB64Str.end());

        // step4: create token with hmac
        std::string signB64;
        auto result = CalSignB64(tokenHeader_.GetAlgTy(), MakeStringView(totalB64), signB64, key, keyLen);
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }

        innerToken.clear();
        std::ostringstream innerTokenOss;
        innerTokenOss << headerB64Str << JWT_SEP_DOT << MakeStringView(payloadB64) << JWT_SEP_DOT << signB64;
        std::string innerTokenStr = innerTokenOss.str();
        innerToken.reserve(innerTokenStr.size());
        std::copy(innerTokenStr.begin(), innerTokenStr.end(), std::back_inserter(innerToken));

        return JwtAuthRC::OK;
    }

    JwtAuthRC CheckCalculateSignature(CryptoHmacAlg algType, const char *key, uint32_t keyLen,
                                      std::string_view totalB64, std::string &signB64) const
    {
        if (CCSEC_UNLIKELY(key == nullptr || keyLen == 0)) {
            CCSEC_LOG_ERROR("|CheckCalculateSignature|END|returnF||key is null or keyLen is 0.");
            return JwtAuthRC::KEY_PASS_INVALID;
        }
        auto [rc, cipher] =
            KmCryptor(options_.keyManagerType).Decrypt(JWT_DEFAULT_SYM_ENC_ALG, {key, keyLen}, options_.domainId);
        if (CCSEC_UNLIKELY(rc != CryptionRC::OK)) {
            CCSEC_LOG_ERROR("|CheckCalculateSignature|END|returnF||key manager decrypt failed");
            return JwtAuthRC::DECRYPT_FAIL;
        }

        auto result =
            CalSignB64(algType, totalB64, signB64, reinterpret_cast<const char *>(cipher.data()), cipher.size());
        (void)memset_s(cipher.data(), cipher.size(), 0, cipher.size());
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }

        return JwtAuthRC::OK;
    }

    static JwtAuthRC CalSignB64(CryptoHmacAlg algType, std::string_view totalB64, std::string &signB64, const char *key,
                                uint32_t keyLen)
    {
        if (CCSEC_UNLIKELY(key == nullptr || keyLen == 0)) {
            CCSEC_LOG_ERROR("Failed to create token as key pass is null.");
            return JwtAuthRC::KEY_PASS_INVALID;
        }

        std::vector<uint8_t> hmac(GetEstimateHmacOutLen(algType));
        auto rc = NativeHmac(algType, {key, keyLen}, totalB64, hmac.data(), nullptr);
        if (CCSEC_UNLIKELY(rc != CryptionRC::OK)) {
            return JwtAuthRC::HMAC_ENCODE_FAIL;
        }

        auto hmacB64 = Base64Encode(reinterpret_cast<const char *>(hmac.data()), hmac.size());
        if (hmacB64.empty()) {
            CCSEC_LOG_ERROR("CalSignB64|END|returnF|base64 encode error.");
            return JwtAuthRC::BASE64_ENCODE_FAIL;
        }
        signB64 = StrUtils::Split(MakeStringView(hmacB64), "=")[0]; // remove the trailing "="

        return JwtAuthRC::OK;
    }

    static JwtAuthRC GetInfoByToken(std::string_view headerStr, int64_t &expireTimeMinute, int64_t &createTimeSec,
                                    CryptoHmacAlg &algType)
    {
        if (CCSEC_UNLIKELY(headerStr.empty())) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|Header string is null.");
            return JwtAuthRC::PARAM_INVALID;
        }

        std::vector<std::string> splitVec;
        StrUtils::Split(headerStr, ";", splitVec);
        if (CCSEC_UNLIKELY(splitVec.empty() || splitVec.size() != NUM_3)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|returnF|Split header string failed.");
            return JwtAuthRC::PARAM_INVALID;
        }

        std::vector<std::string> algVec;
        StrUtils::Split(splitVec[0], ":", algVec);
        if (CCSEC_UNLIKELY(algVec.empty() || algVec.size() != NUM_2)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|Split alt string failed.");
            return JwtAuthRC::PARAM_INVALID;
        }

        auto [rc, out] = GetAlgType(algVec);
        if (CCSEC_UNLIKELY(rc != JwtAuthRC::OK)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|Get alg type failed.");
            return JwtAuthRC::PARAM_INVALID;
        }
        algType = out;

        std::vector<std::string> timeVec;
        StrUtils::Split(splitVec[1], ":", timeVec);
        if (CCSEC_UNLIKELY(timeVec.empty() || timeVec.size() != NUM_2)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|Split expire time string failed.");
            return JwtAuthRC::PARAM_INVALID;
        }

        if (!StrUtils::StrToInt64(timeVec[1], expireTimeMinute)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|Get time failed.");
            return JwtAuthRC::PARAM_INVALID;
        }

        std::vector<std::string> createTimeVec;
        StrUtils::Split(splitVec[NUM_2], ":", createTimeVec);
        if (CCSEC_UNLIKELY(createTimeVec.empty() || createTimeVec.size() != NUM_2)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|Split create time string failed.");
            return JwtAuthRC::PARAM_INVALID;
        }

        if (CCSEC_UNLIKELY(!StrUtils::StrToLong(createTimeVec[1], createTimeSec) ||
                           expireTimeMinute > JWT_EXPIRE_TIME_MAX_MINUTE)) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::GetInfoByToken|Get time failed.");
            return JwtAuthRC::PARAM_INVALID;
        }
        return JwtAuthRC::OK;
    }

    static JwtAuthRC CheckTokenExpiredTime(const std::vector<std::string> &b64Vec, CryptoHmacAlg &algType)
    {
        std::string headDeB64Str;
        TryFixBase64(b64Vec[0], headDeB64Str);

        auto headerData = Base64Decode(headDeB64Str);
        if (headerData.empty()) {
            CCSEC_LOG_ERROR("|JwtAuthServer::Impl::CheckTokenExpiredTime|Base64 decode error");
            return JwtAuthRC::ERROR;
        }

        int64_t expireTimeMinute = 0;
        int64_t createTimeSec = 0;
        auto result = GetInfoByToken(MakeStringView(headerData), expireTimeMinute, createTimeSec, algType);
        if (CCSEC_UNLIKELY(result != JwtAuthRC::OK)) {
            return result;
        }

        struct timespec now = {0, 0};
        clock_gettime(CLOCK_REALTIME, &now);
        if (expireTimeMinute > JWT_EXPIRE_TIME_MAX_MINUTE ||
            (expireTimeMinute != -1 && now.tv_sec >= createTimeSec &&
             (now.tv_sec - createTimeSec) > expireTimeMinute * JWT_SECONDS_PER_MINUTE)) {
            CCSEC_LOG_ERROR("Failed to validate token as token is expired");
            return JwtAuthRC::TOKEN_EXPIRED;
        }

        return JwtAuthRC::OK;
    }

    JwtAuthRC CheckValidateTokenParams(const CDFDistAuthValidateTokenOptions &options) const
    {
        if (!started_) {
            CCSEC_LOG_ERROR("|CheckValidateTokenParams|END|returnF||JwtAuthServer is not started.");
            return JwtAuthRC::ERROR;
        }
        if (CCSEC_UNLIKELY(options.token == nullptr || options.tokenLen == 0)) {
            CCSEC_LOG_ERROR("|CheckValidateTokenParams|returnF|Failed to validate token as token is null.");
            return JwtAuthRC::PARAM_INVALID;
        }

        if (strnlen(options.token, options.tokenLen) != options.tokenLen - 1) {
            CCSEC_LOG_ERROR("|CheckValidateTokenParams|returnF|Failed to validate token as token size is invalid."
                            "hint: " << strnlen(options.token, options.tokenLen) << " vs " << (options.tokenLen - 1));
            return JwtAuthRC::PARAM_INVALID;
        }
        if (options.tokenLen > JWT_INPUT_LENGTH_MAX) {
            CCSEC_LOG_ERROR("|CheckValidateTokenParams|returnF|Failed to validate token, token size is too long. "
                            "current: " << options.tokenLen << ", max: " << JWT_INPUT_LENGTH_MAX);
            return JwtAuthRC::PARAM_INVALID;
        }
        return JwtAuthRC::OK;
    }

    JwtAuthRC CheckCreateTokenParams(const CDFDistAuthCreateTokenOptions &options) const
    {
        if (!started_) {
            CCSEC_LOG_ERROR("|CheckCreateTokenParams|END|returnF||JwtAuthServer is not started.");
            return JwtAuthRC::ERROR;
        }
        // check options
        if (options.input == nullptr || options.inputLen == 0 || options.token == nullptr || options.tokenLen == 0) {
            CCSEC_LOG_ERROR("|CheckCreateTokenParams|returnF|Failed to create token as input is null.");
            return JwtAuthRC::PARAM_INVALID;
        }

        if (strnlen(options.input, options.inputLen) != options.inputLen - 1) {
            CCSEC_LOG_ERROR("|CheckCreateTokenParams|returnF|Key size is invalid. got "
                            << strnlen(options.input, options.inputLen) << " != " << (options.inputLen - 1));
            return JwtAuthRC::PARAM_INVALID;
        }

        if (options.inputLen > JWT_INPUT_LENGTH_MAX) {
            CCSEC_LOG_ERROR("|CheckCreateTokenParams|returnF|Failed to create token, input size is too long. "
                            "current: " << options.inputLen << ", max: " << JWT_INPUT_LENGTH_MAX);
            return JwtAuthRC::PARAM_INVALID;
        }
        return JwtAuthRC::OK;
    }
};

std::mutex JwtAuthServer::Impl::mMutex;

JwtAuthServer::JwtAuthServer() : impl_(std::make_unique<JwtAuthServer::Impl>())
{}

JwtAuthServer::~JwtAuthServer() = default;

JwtAuthRC JwtAuthServer::Start(const CDFDistAuthServerOptions &opt)
{
    return impl_->Start(opt);
}

JwtAuthRC JwtAuthServer::Stop()
{
    return impl_->Stop();
}

JwtAuthRC JwtAuthServer::RefreshEncryptionKey(std::string_view newKey)
{
    return impl_->RefreshEncryptionKey(newKey.data(), newKey.size());
}

JwtAuthRC JwtAuthServer::SetEncryptionKey(std::string_view newKey)
{
    return impl_->SetEncryptionKey(newKey.data(), newKey.size());
}

std::pair<JwtAuthRC, uint32_t> JwtAuthServer::EstimateTokenLength(uint32_t inputLen)
{
    uint32_t out = 0;
    auto rc = impl_->EstimateTokenLength(inputLen, &out);
    return {rc, out};
}

JwtAuthRC JwtAuthServer::CreateToken(CDFDistAuthCreateTokenOptions &options)
{
    return impl_->CreateToken(options);
}

JwtAuthRC JwtAuthServer::ValidateToken(const CDFDistAuthValidateTokenOptions &options)
{
    return impl_->ValidateToken(options);
}

} // namespace cdf
