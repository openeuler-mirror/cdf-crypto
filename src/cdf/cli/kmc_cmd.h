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

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cdf/cli/cmd.h"
#include "cdf/cli/defines.h"
#include "cdf/modules/cryption/define.h"

namespace cdf {

class KmcCmd : public Cmd {
public:
    explicit KmcCmd() = default;

    CryptionToolRc HandleCmd(std::vector<std::string> &cmdParams, const CliConfig &config) override;

    constexpr static char const *PARAMETER_ERROR_INFO = "Parameters error. --encrypt domainId domainCount"
                                                        " || --createkey domainId domainCount"
                                                        " || --displaykey domainId domainCount"
                                                        " || --removekey domainId domainCount keyId"
                                                        " || --reEncrypt domainId domainCount";

    constexpr static int MAX_DOMAIN_COUNT = 1024;
    constexpr static int DOMAIN_ID_INDEX = 0;
    constexpr static int DOMAIN_COUNT_INDEX = 1;
    constexpr static int PLAIN_TEXT_INDEX = 2;

protected:
    CryptionToolRc ParseDomainId(const std::string &domainIdParam, uint32_t domainCount, uint32_t &domainId) const;
    CryptionToolRc ParseDomainIdAndDomainCount(std::vector<std::string> &cmdParams, uint32_t &domainId,
                                               uint32_t &domainCount);
    CryptionToolRc ReadEncryptContent(char *inputPlainText, char *inputPlainTextCheck, int32_t plainTextLength) const;
    CryptionToolRc GetPassFromInput(char *plainText, uint32_t plainTextLength, bool firstType) const;
};

class EncryptKeyCmd : public KmcCmd {
public:
    explicit EncryptKeyCmd() = default;
    CryptionToolRc Encrypt(const CliConfig &config, uint32_t domainId, uint32_t domainCount, char *inputPlainText,
                           std::string &cipherText);
    CryptionToolRc HandleCmd(std::vector<std::string> &cmdParams, const CliConfig &config) override;

private:
    constexpr static const int MAX_KEY_LENGTH = 33;
    constexpr static const int PARAM_COUNT = 2;
};

class ReEncryptCmd : public KmcCmd {
public:
    explicit ReEncryptCmd() = default;
    CryptionToolRc HandleCmd(std::vector<std::string> &cmdParams, const CliConfig &config) override;
    CryptionToolRc ReEncrypt(const CliConfig &config, uint32_t domainId, uint32_t domainCount, char *inputCipherText,
                             std::string &reCipherText);

private:
    constexpr static const int MAX_CIPHER_LENGTH = 150;
    constexpr static const int PARAM_COUNT = 2;
};

class CreateKeyCmd : public KmcCmd {
public:
    explicit CreateKeyCmd() = default;
    CryptionToolRc HandleCmd(std::vector<std::string> &cmdParams, const CliConfig &config) override;
    constexpr static const int PARAM_COUNT = 2;
};

class DisplaykeyCmd : public KmcCmd {
public:
    explicit DisplaykeyCmd() = default;
    CryptionToolRc HandleCmd(std::vector<std::string> &cmdParams, const CliConfig &config) override;
    constexpr static const int PARAM_COUNT = 2;
    constexpr static int DOMAIN_ID_INDEX = 0;
    constexpr static int DOMAIN_COUNT_INDEX = 1;
};

class RemovekeyCmd : public KmcCmd {
public:
    explicit RemovekeyCmd() = default;
    CryptionToolRc HandleCmd(std::vector<std::string> &cmdParams, const CliConfig &config) override;
    constexpr static const int PARAM_COUNT = 3;
    constexpr static int DOMAIN_ID_INDEX = 0;
    constexpr static int DOMAIN_COUNT_INDEX = 1;
    constexpr static int DOMAIN_REMOVE_KEY_INDEX = 2;
};


CryptionToolRc GetBinaryConfigPath(std::string &folder);

} // namespace cdf
