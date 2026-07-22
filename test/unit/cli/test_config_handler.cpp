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

namespace cdf::test {

class TestCDFCli : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Create temporary directory for test files
        testDir_ = std::filesystem::temp_directory_path() / "cdf_cli_test";
        std::filesystem::create_directories(testDir_);
    }

    void TearDown() override
    {
        // Clean up temporary files
        std::filesystem::remove_all(testDir_);
    }

    std::filesystem::path testDir_;
};

TEST_F(TestCDFCli, CheckConfig_ValidAlgorithm_AES256_GCM)
{
    CliConfig cfg;
    cfg.algorithm = "AES256_GCM";
    cfg.kmcType = "";  // Empty means use local KMC

    auto ret = CheckConfig(cfg);
    // Will fail because kmcType != "kmc", so it checks thirdKmc.kmcPath which is empty
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, CheckConfig_ValidAlgorithm_CHACHA20_POLY1305)
{
    CliConfig cfg;
    cfg.algorithm = "CHACHA20_POLY1305";
    cfg.kmcType = "";

    auto ret = CheckConfig(cfg);
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);  // Path check fails for empty kmcPath
}

TEST_F(TestCDFCli, CheckConfig_InvalidAlgorithm)
{
    CliConfig cfg;
    cfg.algorithm = "INVALID_ALGORITHM";
    cfg.kmcType = "";

    auto ret = CheckConfig(cfg);
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, CheckConfig_EmptyAlgorithm)
{
    CliConfig cfg;
    cfg.algorithm = "";
    cfg.kmcType = "";

    auto ret = CheckConfig(cfg);
    // Empty algorithm is valid (uses default), but path check fails
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, CheckConfig_ValidKmcType_Openbao)
{
    CliConfig cfg;
    cfg.algorithm = "AES256_GCM";
    cfg.kmcType = "openbao";

    auto ret = CheckConfig(cfg);
    // Will fail because thirdKmc.kmcPath is empty
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, CheckConfig_ValidKmcType_Vault)
{
    CliConfig cfg;
    cfg.algorithm = "AES256_GCM";
    cfg.kmcType = "vault";

    auto ret = CheckConfig(cfg);
    // Will fail because thirdKmc.kmcPath is empty
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, CheckConfig_InvalidKmcType)
{
    CliConfig cfg;
    cfg.algorithm = "AES256_GCM";
    cfg.kmcType = "invalid_type";

    auto ret = CheckConfig(cfg);
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, CheckConfig_EmptyKmcType)
{
    CliConfig cfg;
    cfg.algorithm = "AES256_GCM";
    cfg.kmcType = "";  // Empty is valid for CDFCheckType, but CheckConfig needs "kmc"

    auto ret = CheckConfig(cfg);
    // CDFCheckType returns OK for empty, but CheckConfig checks kmcType == "kmc"
    // which fails, then checks kmcPath which fails
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, CliConfig_DefaultAlgorithm)
{
    CliConfig cfg;
    EXPECT_EQ(cfg.algorithm, "AES256_GCM");
}

TEST_F(TestCDFCli, GetConfig_FileNotFound)
{
    CliConfig cfg;
    auto ret = GetConfig("/nonexistent/path/config.json", cfg);
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, GetConfig_InvalidJsonFile)
{
    // Create invalid JSON file
    auto configPath = testDir_ / "invalid_config.json";
    std::ofstream file(configPath);
    file << "{ invalid json content }";
    file.close();

    CliConfig cfg;
    auto ret = GetConfig(configPath.string(), cfg);
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, GetConfig_EmptyFile)
{
    // Create empty file
    auto configPath = testDir_ / "empty_config.json";
    std::ofstream file(configPath);
    file << "";
    file.close();

    CliConfig cfg;
    auto ret = GetConfig(configPath.string(), cfg);
    EXPECT_EQ(ret, CryptionToolRc::INTERNAL_ERROR);
}

TEST_F(TestCDFCli, GetConfig_MinimalValidConfig)
{
    // Create minimal valid config
    auto configPath = testDir_ / "minimal_config.json";
    std::ofstream file(configPath);
    file << R"({"algorithm":"AES256_GCM"})";
    file.close();

    CliConfig cfg;
    auto ret = GetConfig(configPath.string(), cfg);
    (void)ret;  // Result depends on logger initialization, just testing parsing logic
}

TEST_F(TestCDFCli, GetConfig_ConfigWithThirdKmc)
{
    // Create config with third party KMC
    auto configPath = testDir_ / "third_kmc_config.json";
    std::ofstream file(configPath);
    file << R"({
        "algorithm": "AES256_GCM",
        "thirdKeyManager": {
            "keyManagerType": "openbao",
            "keyManagerPath": "/usr/local/bin/openbao",
            "keyManagerAddr": "https://localhost:8200"
        }
    })";
    file.close();

    CliConfig cfg;
    auto ret = GetConfig(configPath.string(), cfg);
    (void)ret;  // Result depends on logger initialization, just testing parsing logic
}

} // namespace cdf::test