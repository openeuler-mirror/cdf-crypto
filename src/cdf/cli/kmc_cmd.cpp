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

#include "cdf/cli/kmc_cmd.h"

#include <libgen.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "securec.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"
#include "cdf/cli/defines.h"
#include "cdf/modules/cryption/define.h"
#include "cdf/modules/cryption/km_cryptor.h"
#include "cdf/modules/key_management/define.h"
#include "cdf/modules/key_management/key_manager.h"
#include "cdf/modules/key_management/key_manager_factory.h"
#include "cdf/modules/key_management/openbao/openbao_key_manager.h"
#include "cdf/modules/key_management/vault/vault_key_manager.h"
#include "cdf/utils/file_utils.h"
#include "cdf/utils/str_utils.h"

namespace cdf {
namespace {

inline CryptoSymAlg ConfigParseCryptoAlg(const CliConfig &config)
{
    if (config.algorithm == "AES128_GCM") {
        return CryptoSymAlg::AES128_GCM;
    } else if (config.algorithm == "AES256_GCM") {
        return CryptoSymAlg::AES256_GCM;
    } else if (config.algorithm == "SM4_CTR") {
        return CryptoSymAlg::SM4_CTR;
    } else if (config.algorithm == "AES128_CCM") {
        return CryptoSymAlg::AES128_CCM;
    } else if (config.algorithm == "CHACHA20_POLY1305") {
        return CryptoSymAlg::CHACHA20_POLY1305;
    } else {
        return CryptoSymAlg::UNKNOWN;
    }
}

CryptionToolRc GetAccessTokenFromInput(char *accessToken, uint32_t accessTokenLen)
{
    struct termios tty;
    struct termios ttySave;
    tcgetattr(STDIN_FILENO, &tty);
    tcgetattr(STDIN_FILENO, &ttySave);
    tty.c_lflag &= ~ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    std::cout << "please type in your openbao/vault access token" << std::endl;

    uint32_t index = 0;
    char ch = static_cast<char>(std::cin.get());
    while (ch != '\n' && ch != '\r' && ch != '\0' && index < accessTokenLen - 1) {
        accessToken[index] = ch;
        ch = std::cin.get();
        index++;
    }
    accessToken[index] = '\0';

    (void)tcsetattr(STDIN_FILENO, TCSANOW, &ttySave);

    if (index == 0) {
        CCSEC_LOG_ERROR("|check input key|END|returnF||Input key can not be empty, index = " << index);
        return CryptionToolRc::PARAM_INVALID;
    }
    if (index == accessTokenLen - 1) {
        CCSEC_LOG_ERROR("|check input key|END|returnF||Input key is too long.");
        return CryptionToolRc::PARAM_INVALID;
    }
    return CryptionToolRc::OK;
}

KeyManager *GetKm(const CliConfig &config)
{
    if (config.kmcType == "openbao") {
        return KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    } else if (config.kmcType == "vault") {
        return KeyManagerFactory::Borrow(KeyManagerTy::VAULT);
    } else {
        return KeyManagerFactory::Borrow(KeyManagerTy::UNKNOWN);
    }
}

CryptionToolRc InitKm(const CliConfig &config, KeyManager *km, uint32_t domainCount)
{
    if (km == nullptr) {
        CCSEC_LOG_ERROR("|InitKm|END|returnF||KeyManager is nullptr");
        return CryptionToolRc::PARAM_INVALID;
    }
    constexpr int defaultAccessTokenLen = 128;
    std::vector<char> accessToken(defaultAccessTokenLen);
    auto rc = GetAccessTokenFromInput(accessToken.data(), accessToken.size());
    if (rc != CryptionToolRc::OK) {
        return rc;
    }
    accessToken.resize(strlen(accessToken.data()));

    // init openbao
    auto ret = km->Init(config.thirdKmc.kmcPath, MakeStringView(accessToken), domainCount);
    (void)memset_s(accessToken.data(), accessToken.size(), 0, accessToken.size());
    if (ret != KeyManagerRC::OK) {
        return CryptionToolRc::ENCRYPT_ERROR;
    }

    return CryptionToolRc::OK;
}

CryptionToolRc PrepareKmDomainKey(KeyManager *km, uint32_t domainId)
{
    uint32_t keyId;
    switch (km->Type()) {
        case KeyManagerTy::OPENBAO: {
            if (static_cast<OpenbaoKeyManager *>(km)->GetLatestKey(domainId, keyId).empty()) {
                CCSEC_LOG_WARN("Trying to create a key for domain " << domainId << " since it's empty");
                km->CreateKey(domainId);
            }
            break;
        }

        case KeyManagerTy::VAULT: {
            if (static_cast<VaultKeyManager *>(km)->GetLatestKey(domainId, keyId).empty()) {
                CCSEC_LOG_WARN("Trying to create a key for domain " << domainId << " since it's empty");
                km->CreateKey(domainId);
            }
            break;
        }
        default:
            CCSEC_LOG_ERROR("Unknown key manager type");
            return CryptionToolRc::INTERNAL_ERROR;
    }

    return CryptionToolRc::OK;
}
} // namespace

CryptionToolRc GetBinaryConfigPath(std::string &folder)
{
    std::array<char, PATH_MAX + 1> filePath = {0};
    if (readlink("/proc/self/exe", filePath.data(), PATH_MAX) == -1) {
        CCSEC_LOG_ERROR("|readlink|END|returnF||Readlink '/proc/self/exe' "
                        "failed, program binary locate failed.");
        return CryptionToolRc::INTERNAL_ERROR;
    }

    char *dirPath = dirname(filePath.data());
    if (dirPath == nullptr) {
        CCSEC_LOG_ERROR("|dirPath|END|returnF||DirPath /proc/self/exe failed.");
        return CryptionToolRc::INTERNAL_ERROR;
    }

    std::array<char, PATH_MAX + 1> tmpPath = {0};
    if (sprintf_s(tmpPath.data(), PATH_MAX, "%s%s", dirPath, "/../config/") < 0) {
        CCSEC_LOG_ERROR("|get config path|END|returnF||Get config path base on " << std::string(dirPath) << " failed.");
        return CryptionToolRc::INTERNAL_ERROR;
    }

    if (realpath(tmpPath.data(), filePath.data()) == nullptr) {
        CCSEC_LOG_ERROR("|check config path|END|returnF||Check config path " << std::string(tmpPath.data()) << " "
                        "failed, access deny.");
        return CryptionToolRc::INTERNAL_ERROR;
    }

    folder = std::string(filePath.data());
    return CryptionToolRc::OK;
}
CryptionToolRc KmcCmd::ParseDomainId(const std::string &domainIdParam, uint32_t domainCount, uint32_t &domainId) const
{
    uint32_t value = 0;
    auto ret = StrUtils::StrToU32(domainIdParam, value);
    if (!ret) {
        CCSEC_LOG_ERROR("|domainId parameter|END|returnF||DomainId parameter error.");
        return CryptionToolRc::PARAM_INVALID;
    }

    if (value >= domainCount) {
        CCSEC_LOG_ERROR("|domainId parameter|END|returnF||DomainId parameter error.");
        return CryptionToolRc::PARAM_INVALID;
    }
    domainId = value;
    return CryptionToolRc::OK;
}

CryptionToolRc KmcCmd::ParseDomainIdAndDomainCount(std::vector<std::string> &cmdParams, uint32_t &domainIdInt,
                                                   uint32_t &domainCountInt)
{
    std::string domainId = cmdParams[DOMAIN_ID_INDEX];
    std::string domainCount = cmdParams[DOMAIN_COUNT_INDEX];
    auto parseRet = StrUtils::StrToU32(domainCount, domainCountInt);
    if (!parseRet) {
        std::cout << "Domain count parse error." << std::endl;
        CCSEC_LOG_ERROR("|domain count parse|END|returnF||Domain count parse error.");
        return CryptionToolRc::PARAM_INVALID;
    }

    auto ret = ParseDomainId(domainId, domainCountInt, domainIdInt);
    if (ret != CryptionToolRc::OK) {
        std::cout << "Failed to parse domain id." << std::endl;
        CCSEC_LOG_ERROR("|parse domain id|END|returnF||Failed to parse domain id.");
        return CryptionToolRc::PARAM_INVALID;
    }
    return CryptionToolRc::OK;
}

CryptionToolRc KmcCmd::HandleCmd(std::vector<std::string> &cmdParams, [[maybe_unused]] const CliConfig &config)
{
    (void)cmdParams;
    CCSEC_LOG_ERROR(PARAMETER_ERROR_INFO);
    return CryptionToolRc::OK;
}

CryptionToolRc EncryptKeyCmd::HandleCmd(std::vector<std::string> &cmdParams, [[maybe_unused]] const CliConfig &config)
{
    if (cmdParams.size() != PARAM_COUNT) {
        std::cout << "Parameter number error." << std::endl;
        CCSEC_LOG_ERROR("|parameter number|END|returnF||Parameter number error.");
        return CryptionToolRc::PARAM_INVALID;
    }
    uint32_t domainId = 0;
    uint32_t domainCount = 0;
    auto ret = ParseDomainIdAndDomainCount(cmdParams, domainId, domainCount);
    if (ret != CryptionToolRc::OK) {
        std::cout << "Failed to parse args" << std::endl;
        CCSEC_LOG_ERROR("|parse args|END|returnF||Failed to parse args.");
        return CryptionToolRc::PARAM_INVALID;
    }

    char inputPlainText[MAX_KEY_LENGTH] = {0};
    char inputPlainTextCheck[MAX_KEY_LENGTH] = {0};
    if (ReadEncryptContent(inputPlainText, inputPlainTextCheck, MAX_KEY_LENGTH) != CryptionToolRc::OK) {
        std::cout << "Failed to read content." << std::endl;
        return CryptionToolRc::PARAM_INVALID;
    }
    std::string cipherText;

    ret = Encrypt(config, domainId, domainCount, inputPlainText, cipherText);
    (void)memset_s(inputPlainText, MAX_KEY_LENGTH, 0, MAX_KEY_LENGTH);
    if (ret != CryptionToolRc::OK) {
        std::cout << "Failed to encrypt." << std::endl;
        CCSEC_LOG_ERROR("|encrypt|END|returnF||Failed to encrypt.");
        return CryptionToolRc::PARAM_INVALID;
    }

    std::cout << "encrypted: " << cipherText << std::endl;

    return CryptionToolRc::OK;
}

CryptionToolRc EncryptKeyCmd::Encrypt(const CliConfig &config, uint32_t domainId, uint32_t domainCount,
                                      char *inputPlainText, std::string &cipherText)
{
    auto *km = GetKm(config);
    if (InitKm(config, km, domainCount) == CryptionToolRc::OK) {
        auto tmpRc = PrepareKmDomainKey(km, domainId);
        if (tmpRc != CryptionToolRc::OK) {
            return tmpRc;
        }
        CryptionRC rc;
        std::vector<std::byte> cipherTextVec;
        auto cryptor = KmCryptor(km);
        std::tie(rc, cipherTextVec) = cryptor.Encrypt(ConfigParseCryptoAlg(config), inputPlainText, domainId);
        km->UnInit();
        if (rc != CryptionRC::OK) {
            CCSEC_LOG_ERROR("|encrypt key||||Failed to encrypt, ret is: " << (int)rc);

            return CryptionToolRc::ENCRYPT_ERROR;
        }
        cipherText = std::string(reinterpret_cast<const char *>(cipherTextVec.data()), cipherTextVec.size());
        return CryptionToolRc::OK;
    }
    CCSEC_LOG_ERROR("|init cryption instance|END|returnF||Init cryption instance failed.");
    return CryptionToolRc::INTERNAL_ERROR;
}

CryptionToolRc CheckDomainKey(KeyManager *km, uint32_t domainId)
{
    uint32_t keyId;
    switch (km->Type()) {
        case KeyManagerTy::OPENBAO: {
            if (static_cast<OpenbaoKeyManager *>(km)->GetLatestKey(domainId, keyId).empty()) {
                CCSEC_LOG_ERROR("CheckDomainKey|END|returnF|domainId no openbao keys");
                return CryptionToolRc::PARAM_INVALID;
            }
            break;
        }

        case KeyManagerTy::VAULT: {
            if (static_cast<VaultKeyManager *>(km)->GetLatestKey(domainId, keyId).empty()) {
                CCSEC_LOG_ERROR("CheckDomainKey|END|returnF|domainId no vault keys");
                return CryptionToolRc::PARAM_INVALID;
            }
            break;
        }
        default:
            CCSEC_LOG_ERROR("CheckDomainKey|END|returnF|Unknown key manager type");
            return CryptionToolRc::INTERNAL_ERROR;
    }
    return CryptionToolRc::OK;
}

CryptionToolRc ReEncryptCmd::ReEncrypt(const CliConfig &config, uint32_t domainId, uint32_t domainCount,
                                       char *inputCipherText, std::string &reCipherText)
{
    auto *km = GetKm(config);
    if (InitKm(config, km, domainCount) == CryptionToolRc::OK) {
        auto tmpRc = CheckDomainKey(km, domainId);
        if (tmpRc != CryptionToolRc::OK) {
            return tmpRc;
        }

        auto cryptor = KmCryptor(km);
        auto [rc, plaintext] = cryptor.Decrypt(ConfigParseCryptoAlg(config), inputCipherText, domainId);
        if (rc != CryptionRC::OK) {
            (void)memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());
            CCSEC_LOG_ERROR("|decrypt key||||Failed to decrypt key, ret code: " << (int)rc);
            km->UnInit();
            return CryptionToolRc::ENCRYPT_ERROR;
        }

        std::vector<std::byte> reCipherTextVec;
        std::tie(rc, reCipherTextVec) =
            cryptor.Encrypt(ConfigParseCryptoAlg(config), MakeStringView(plaintext), domainId);
        (void)memset_s(plaintext.data(), plaintext.size(), 0, plaintext.size());
        if (rc != CryptionRC::OK) {
            CCSEC_LOG_ERROR("|encrypt key||||Failed to encrypt key, ret is: " << (int)rc);
            km->UnInit();
            return CryptionToolRc::ENCRYPT_ERROR;
        }
        reCipherText = std::string(reinterpret_cast<const char *>(reCipherTextVec.data()), reCipherTextVec.size());
        reCipherTextVec.clear();
        km->UnInit();
        return CryptionToolRc::OK;
    }

    CCSEC_LOG_ERROR("|init cryption instance|END|returnF||Init cryption instance failed.");
    return CryptionToolRc::INTERNAL_ERROR;
}

CryptionToolRc ReEncryptCmd::HandleCmd(std::vector<std::string> &cmdParams, [[maybe_unused]] const CliConfig &config)
{
    if (cmdParams.size() != PARAM_COUNT) {
        CCSEC_LOG_ERROR("|parameter number|END|returnF||Parameter number error.");
        return CryptionToolRc::PARAM_INVALID;
    }
    uint32_t domainId = 0;
    uint32_t domainCount = 0;
    auto ret = ParseDomainIdAndDomainCount(cmdParams, domainId, domainCount);
    if (ret != CryptionToolRc::OK) {
        std::cout << "Failed to parse args" << std::endl;
        CCSEC_LOG_ERROR("|parse args|END|returnF||Failed to parse args.");
        return CryptionToolRc::PARAM_INVALID;
    }

    char inputCipherText[MAX_CIPHER_LENGTH] = {0};
    char inputCipherTextCheck[MAX_CIPHER_LENGTH] = {0};
    if (ReadEncryptContent(inputCipherText, inputCipherTextCheck, MAX_CIPHER_LENGTH) != CryptionToolRc::OK) {
        std::cout << "Failed to read encrypt content" << std::endl;
        CCSEC_LOG_ERROR("|read encrypt content|END|returnF||Failed to read encrypt content.");
        return CryptionToolRc::PARAM_INVALID;
    }

    std::string reCipherText;
    ret = ReEncrypt(config, domainId, domainCount, inputCipherText, reCipherText);
    if (ret != CryptionToolRc::OK) {
        CCSEC_LOG_ERROR("|reEncrypt||||Failed to reEncrypt.");
    } else {
        std::cout << "success to reEncrypt: " << reCipherText << std::endl;
        CCSEC_LOG_INFO("|reEncrypt|END|returnS||success to reEncrypt.");
    }
    return ret;
}

CryptionToolRc KmcCmd::ReadEncryptContent(char *inputPlainText, char *inputPlainTextCheck,
                                          int32_t plainTextLength) const
{
    struct termios tty;
    struct termios ttySave;
    tcgetattr(STDIN_FILENO, &tty);
    tcgetattr(STDIN_FILENO, &ttySave);
    tty.c_lflag &= ~ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    if (GetPassFromInput(inputPlainText, plainTextLength, true) != CryptionToolRc::OK) {
        CCSEC_LOG_ERROR("|get password||||Failed to get password.");
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &ttySave);
        (void)memset_s(inputPlainText, plainTextLength, 0, plainTextLength);
        return CryptionToolRc::PARAM_INVALID;
    }

    if (GetPassFromInput(inputPlainTextCheck, plainTextLength, false) != CryptionToolRc::OK) {
        CCSEC_LOG_ERROR("|get password||||Failed to get password.");
        (void)memset_s(inputPlainText, plainTextLength, 0, plainTextLength);
        (void)memset_s(inputPlainTextCheck, plainTextLength, 0, plainTextLength);
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &ttySave);
        return CryptionToolRc::PARAM_INVALID;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &ttySave);

    if (strcmp(inputPlainText, inputPlainTextCheck) != 0) {
        (void)memset_s(inputPlainText, plainTextLength, 0, plainTextLength);
        (void)memset_s(inputPlainTextCheck, plainTextLength, 0, plainTextLength);
        std::cout << "password not match, please input right password" << std::endl;
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &ttySave);
        return CryptionToolRc::PARAM_INVALID;
    }
    (void)memset_s(inputPlainTextCheck, plainTextLength, 0, plainTextLength);
    return CryptionToolRc::OK;
}

CryptionToolRc KmcCmd::GetPassFromInput(char *plainText, uint32_t plainTextLength, bool firstType) const
{
    if (firstType) {
        std::cout << "please input the password to encrypt" << std::endl;
    } else {
        std::cout << "please input the password to encrypt again" << std::endl;
    }

    uint32_t index = 0;
    char ch = static_cast<char>(std::cin.get());
    while (ch != '\n' && ch != '\r' && ch != '\0' && index < plainTextLength - 1) {
        plainText[index] = ch;
        ch = std::cin.get();
        index++;
    }
    plainText[index] = '\0';
    if (index == 0) {
        CCSEC_LOG_ERROR("|check input key|END|returnF||Input key can not be empty.");
        return CryptionToolRc::PARAM_INVALID;
    }
    if (index == plainTextLength - 1) {
        CCSEC_LOG_ERROR("|check input key|END|returnF||Input key is too long.");
        return CryptionToolRc::PARAM_INVALID;
    }
    return CryptionToolRc::OK;
}

bool IsLinkFileOrDir(const std::string &path)
{
    struct stat stFileAttr {};
    lstat(path.c_str(), &stFileAttr);
    if (S_ISLNK(stFileAttr.st_mode)) {
        return true;
    }

    if (S_ISDIR(stFileAttr.st_mode)) {
        return true;
    }
    return false;
}

uint64_t GetFileLength(const std::string &path)
{
    struct stat st {};

    // 获取文件信息
    if (stat(path.c_str(), &st) == -1) {
        std::cout << "Failed to open file, path: " << path << std::endl;
        return -1;
    }

    return st.st_size;
}

CryptionToolRc ReadFile(const std::string &path, char *content, uint32_t contentLength)
{
    if (content == nullptr) {
        CCSEC_LOG_ERROR("|read file|END|returnF|content is nullptr");
        return CryptionToolRc::PARAM_INVALID;
    }
    auto [ret, realPath] = FileUtils::CanonicalPath(path);
    if (!ret) {
        CCSEC_LOG_ERROR("|open file|END|returnF|failed to get canonical path, given: " << path);
        return CryptionToolRc::INTERNAL_ERROR;
    }
    std::ifstream in(realPath);
    if (!in.is_open()) {
        CCSEC_LOG_ERROR("|open file|END|returnF|path is: " << path << "|Failed to open file.");
        return CryptionToolRc::INTERNAL_ERROR;
    }
    std::istreambuf_iterator<char> begin(in);
    std::istreambuf_iterator<char> end;
    uint32_t idx = 0;
    for (std::istreambuf_iterator<char> iterator = begin; iterator != end && idx < contentLength; iterator++) {
        content[idx++] = *iterator;
    }
    in.close();
    if (idx == contentLength) {
        return CryptionToolRc::PARAM_INVALID;
    }
    content[idx] = '\0';
    return CryptionToolRc::OK;
}

CryptionToolRc WriteFile(const std::string &path, const std::string &content)
{
    auto [ret, realPath] = FileUtils::CanonicalPath(path);
    if (!ret) {
        CCSEC_LOG_ERROR("|open file|END|returnF|failed to get canonical path, given: " << path);
        return CryptionToolRc::INTERNAL_ERROR;
    }
    std::ofstream out(realPath);
    if (!out.is_open()) {
        CCSEC_LOG_ERROR("|open file|END|returnF|path is: " << path << "|Failed to open file.");
        return CryptionToolRc::INTERNAL_ERROR;
    }
    out << content;
    out.flush();
    out.close();
    return CryptionToolRc::OK;
}

CryptionToolRc CreateKeyCmd::HandleCmd(std::vector<std::string> &cmdParams, [[maybe_unused]] const CliConfig &config)
{
    auto *km = GetKm(config);
    if (cmdParams.size() != PARAM_COUNT) {
        std::cout << "Parameter number error." << std::endl;
        CCSEC_LOG_ERROR("|parameter number|END|returnF||Parameter number error.");
        return CryptionToolRc::PARAM_INVALID;
    }
    uint32_t domainId = 0;
    uint32_t domainCount = 0;
    auto ret = ParseDomainIdAndDomainCount(cmdParams, domainId, domainCount);
    if (ret != CryptionToolRc::OK) {
        std::cout << "Failed to parse args" << std::endl;
        CCSEC_LOG_ERROR("|parse args|END|returnF||Failed to parse args.");
        return CryptionToolRc::PARAM_INVALID;
    }

    if (InitKm(config, km, domainCount) == CryptionToolRc::OK) {
        auto result = km->CreateKey(domainId);
        km->UnInit();
        if (result.first != KeyManagerRC::OK) {
            std::cout << "Failed to create key, ret:" << static_cast<int>(result.first) << std::endl;
            CCSEC_LOG_ERROR("|create key|END|returnF||Failed to create key, ret is:" << (int)result.first);
            return CryptionToolRc::ACTIVE_KEY_ERROR;
        }
    } else {
        std::cout << "Failed to create key" << std::endl;
        CCSEC_LOG_ERROR("|create key|END|returnF||Failed to create key.");
        return CryptionToolRc::ENCRYPT_INTERNAL_ERROR;
    }
    CCSEC_LOG_INFO("|create key|END|returnS||Create key success.");
    return CryptionToolRc::OK;
}

CryptionToolRc DisplaykeyCmd::HandleCmd(std::vector<std::string> &cmdParams, [[maybe_unused]] const CliConfig &config)
{
    auto *km = GetKm(config);
    if (cmdParams.size() != PARAM_COUNT) {
        CCSEC_LOG_ERROR("|parameter number|END|returnF||Parameter number error.");
        std::cout << "Parameter number error." << std::endl;
        return CryptionToolRc::PARAM_INVALID;
    }
    uint32_t domainId = 0;
    uint32_t domainCount = 0;
    auto ret = ParseDomainIdAndDomainCount(cmdParams, domainId, domainCount);
    if (ret != CryptionToolRc::OK) {
        std::cout << "Failed to parse args" << std::endl;
        CCSEC_LOG_ERROR("|parse args|END|returnF||Failed to parse args.");
        return CryptionToolRc::PARAM_INVALID;
    }

    if (InitKm(config, km, domainCount) == CryptionToolRc::OK) {
        auto result = km->DisplayKey(domainId);
        km->UnInit();
        if (result != KeyManagerRC::OK) {
            std::cout << "Failed to display key" << std::endl;
            CCSEC_LOG_ERROR("|display key|END|returnF||Failed to display key, ret is: " << (int)result);
            return CryptionToolRc::ACTIVE_KEY_ERROR;
        }
    } else {
        std::cout << "Failed to display key" << std::endl;
        return CryptionToolRc::ENCRYPT_INTERNAL_ERROR;
    }
    CCSEC_LOG_INFO("|display key|END|returnS||Display key success.");
    return CryptionToolRc::OK;
}

CryptionToolRc RemovekeyCmd::HandleCmd(std::vector<std::string> &cmdParams, [[maybe_unused]] const CliConfig &config)
{
    auto *km = GetKm(config);
    if (cmdParams.size() != PARAM_COUNT) {
        CCSEC_LOG_ERROR("|parameter number|END|returnF||Parameter number error.");
        std::cout << "Parameter number error." << std::endl;
        return CryptionToolRc::PARAM_INVALID;
    }

    uint32_t domainId = 0;
    uint32_t domainCount = 0;
    auto ret = ParseDomainIdAndDomainCount(cmdParams, domainId, domainCount);
    if (ret != CryptionToolRc::OK) {
        std::cout << "Failed to parse args" << std::endl;
        CCSEC_LOG_ERROR("|parse args|END|returnF||Failed to parse args.");
        return CryptionToolRc::PARAM_INVALID;
    }
    uint32_t keyId = 0;
    auto parseRet = StrUtils::StrToU32(cmdParams[DOMAIN_REMOVE_KEY_INDEX], keyId);
    if (!parseRet) {
        std::cout << "keyId parse error." << std::endl;
        CCSEC_LOG_ERROR("|keyId parse|END|returnF||KeyId parse error.");
        return CryptionToolRc::PARAM_INVALID;
    }

    if (InitKm(config, km, domainCount) == CryptionToolRc::OK) {
        auto result = km->RemoveKey(domainId, keyId);
        km->UnInit();
        if (result != KeyManagerRC::OK) {
            std::cout << "Failed to remove key, ret:" << static_cast<int>(result) << std::endl;
            CCSEC_LOG_ERROR("|remove key|END|returnF||Failed to remove key, ret is: " << (int)result);
            return CryptionToolRc::ACTIVE_KEY_ERROR;
        }
    } else {
        std::cout << "Failed to remove key" << std::endl;
        return CryptionToolRc::ENCRYPT_INTERNAL_ERROR;
    }
    CCSEC_LOG_INFO("|remove key|END|returnS||Remove key success.");
    return CryptionToolRc::OK;
}

} // namespace cdf
