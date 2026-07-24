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

#include <filesystem>
#include <fstream>
#include <string>

#include "gtest/gtest.h"

#include "cdf/cli/config_handler.h"
#include "temp_directory.h"

namespace cdf {
CryptionToolRc ConfigKMC(const rapidjson::Document &configDoc, CliConfig &cfg);
}

namespace cdf::test {

rapidjson::Document ParseConfig(const char *json)
{
    rapidjson::Document document;
    document.Parse(json);
    return document;
}

TEST(ConfigKmcTest, RejectsNonStringAlgorithm)
{
    auto document = ParseConfig(R"({"algorithm":1,"keyManagerType":"openbao"})");
    ASSERT_FALSE(document.HasParseError());
    CliConfig config;

    EXPECT_EQ(ConfigKMC(document, config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(ConfigKmcTest, RejectsMissingKeyManagerType)
{
    auto document = ParseConfig(R"({"algorithm":"AES256_GCM"})");
    ASSERT_FALSE(document.HasParseError());
    CliConfig config;

    EXPECT_EQ(ConfigKMC(document, config), CryptionToolRc::PARAM_INVALID);
}

TEST(ConfigKmcTest, RejectsNonObjectThirdKeyManager)
{
    auto document = ParseConfig(
        R"({"algorithm":"AES256_GCM","keyManagerType":"openbao","thirdKeyManager":[]})");
    ASSERT_FALSE(document.HasParseError());
    CliConfig config;

    EXPECT_EQ(ConfigKMC(document, config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(ConfigKmcTest, ReadsSupportedFields)
{
    auto document = ParseConfig(R"({
        "algorithm":"CHACHA20_POLY1305",
        "keyManagerType":"vault",
        "thirdKeyManager":{
            "keyManagerPath":"/usr/bin/vault",
            "keyManagerAddr":"https://127.0.0.1:8200"
        }
    })");
    ASSERT_FALSE(document.HasParseError());
    CliConfig config;

    ASSERT_EQ(ConfigKMC(document, config), CryptionToolRc::OK);
    EXPECT_EQ(config.algorithm, "CHACHA20_POLY1305");
    EXPECT_EQ(config.kmcType, "vault");
    EXPECT_EQ(config.thirdKmc.kmcPath, "/usr/bin/vault");
    EXPECT_EQ(config.thirdKmc.kmcAddr, "https://127.0.0.1:8200");
}

TEST(ConfigKmcTest, AppliesDefaultsWhenOptionalFieldsAreMissingOrWrongType)
{
    auto document = ParseConfig(R"({
        "keyManagerType":"openbao",
        "thirdKeyManager":{"keyManagerPath":7, "keyManagerAddr":false}
    })");
    ASSERT_FALSE(document.HasParseError());
    CliConfig config;

    ASSERT_EQ(ConfigKMC(document, config), CryptionToolRc::OK);
    EXPECT_EQ(config.algorithm, "AES256_GCM");
    EXPECT_EQ(config.kmcType, "openbao");
    EXPECT_TRUE(config.thirdKmc.kmcPath.empty());
    EXPECT_TRUE(config.thirdKmc.kmcAddr.empty());

    auto noThird = ParseConfig(R"({"algorithm":"AES128_GCM","keyManagerType":"vault"})");
    ASSERT_EQ(ConfigKMC(noThird, config), CryptionToolRc::OK);
    EXPECT_EQ(config.algorithm, "AES128_GCM");
    EXPECT_EQ(config.kmcType, "vault");
}

TEST(ConfigKmcTest, LeavesTypeEmptyWhenConfiguredWithWrongJsonType)
{
    auto document = ParseConfig(R"({"algorithm":"AES256_GCM","keyManagerType":7})");
    CliConfig config;

    EXPECT_EQ(ConfigKMC(document, config), CryptionToolRc::OK);
    EXPECT_TRUE(config.kmcType.empty());
}

TEST(CheckConfigTest, RejectsUndocumentedLocalKmc)
{
    CliConfig config;
    config.algorithm = "AES256_GCM";
    config.kmcType = "kmc";

    EXPECT_EQ(CheckConfig(config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(CheckConfigTest, RejectsInvalidAlgorithm)
{
    CliConfig config;
    config.algorithm = "INVALID_ALGORITHM";
    config.kmcType = "kmc";

    EXPECT_EQ(CheckConfig(config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(CheckConfigTest, RejectsInvalidKeyManagerType)
{
    CliConfig config;
    config.algorithm = "AES256_GCM";
    config.kmcType = "invalid_type";

    EXPECT_EQ(CheckConfig(config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(CheckConfigTest, AcceptsExecutableOpenBaoPath)
{
    TempDirectory temp;
    auto executable = temp.Path() / "bao";
    std::ofstream(executable) << "#!/bin/sh\n";
    std::filesystem::permissions(executable, std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);

    CliConfig config;
    config.algorithm = "AES256_GCM";
    config.kmcType = "openbao";
    config.thirdKmc.kmcPath = executable.string();

    EXPECT_EQ(CheckConfig(config), CryptionToolRc::OK);
}

TEST(CheckConfigTest, RejectsRelativeOpenBaoPath)
{
    CliConfig config;
    config.algorithm = "AES256_GCM";
    config.kmcType = "openbao";
    config.thirdKmc.kmcPath = "relative/bao";

    EXPECT_EQ(CheckConfig(config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(CheckConfigTest, AcceptsEveryDocumentedAlgorithmAndBackend)
{
    TempDirectory temp;
    auto executable = temp.Path() / "km";
    std::ofstream(executable) << "#!/bin/sh\n";
    std::filesystem::permissions(executable, std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);

    for (const char *algorithm : {"AES128_GCM", "AES256_GCM", "SM4_CTR", "AES128_CCM", "CHACHA20_POLY1305"}) {
        for (const char *type : {"openbao", "vault"}) {
            CliConfig config;
            config.algorithm = algorithm;
            config.kmcType = type;
            config.thirdKmc.kmcPath = executable.string();
            EXPECT_EQ(CheckConfig(config), CryptionToolRc::OK) << algorithm << '/' << type;
        }
    }
}

TEST(CheckConfigTest, RejectsNonExecutableDirectoryAndNormalizedPaths)
{
    TempDirectory temp;
    auto plain = temp.Path() / "plain";
    std::ofstream(plain) << "data";
    std::filesystem::permissions(plain, std::filesystem::perms::owner_read,
        std::filesystem::perm_options::replace);

    CliConfig config;
    config.algorithm = "AES256_GCM";
    config.kmcType = "openbao";
    config.thirdKmc.kmcPath = plain.string();
    EXPECT_EQ(CheckConfig(config), CryptionToolRc::INTERNAL_ERROR);
    config.thirdKmc.kmcPath = temp.Path().string();
    EXPECT_EQ(CheckConfig(config), CryptionToolRc::INTERNAL_ERROR);
    config.thirdKmc.kmcPath = temp.Path().string() + "/../missing";
    EXPECT_EQ(CheckConfig(config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(CliConfigTest, UsesAes256GcmByDefault)
{
    CliConfig config;
    EXPECT_EQ(config.algorithm, "AES256_GCM");
}

TEST(GetConfigTest, RejectsMissingFile)
{
    CliConfig config;
    EXPECT_EQ(GetConfig("/nonexistent/path/config.json", config), CryptionToolRc::INTERNAL_ERROR);
}

TEST(GetConfigTest, RejectsInvalidJson)
{
    TempDirectory temp;
    auto configPath = temp.Path() / "invalid.json";
    std::ofstream(configPath) << "{ invalid json content }";
    CliConfig config;

    EXPECT_EQ(GetConfig(configPath.string(), config), CryptionToolRc::INTERNAL_ERROR);
}

} // namespace cdf::test
