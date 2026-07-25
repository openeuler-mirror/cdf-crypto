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

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "gtest/gtest.h"

#include "cdf/cli/defines.h"
#include "cdf/cli/kmc_cmd.h"

int UtEncryptToolMain(int argc, char *argv[]);

namespace cdf::test {
namespace {

class ScopedToolConfig {
public:
    explicit ScopedToolConfig(const std::string &content)
    {
        std::error_code error;
        auto binary = std::filesystem::read_symlink("/proc/self/exe", error);
        if (error) {
            return;
        }
        auto folder = binary.parent_path().parent_path() / "config";
        std::filesystem::create_directories(folder, error);
        if (error) {
            return;
        }
        path_ = folder / "crypto_tool_config.json";
        if (std::filesystem::exists(path_)) {
            std::ifstream input(path_);
            backup_ = std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
            hadOriginal_ = true;
        }
        std::ofstream(path_) << content;
    }

    ~ScopedToolConfig()
    {
        if (path_.empty()) {
            return;
        }
        if (hadOriginal_) {
            std::ofstream(path_) << backup_;
        } else {
            std::error_code error;
            std::filesystem::remove(path_, error);
        }
    }

private:
    std::filesystem::path path_;
    std::string backup_;
    bool hadOriginal_ = false;
};

int RunTool(const char *command)
{
    char app[] = "crypto_tool";
    std::string mutableCommand(command);
    char *argv[] = {app, mutableCommand.data()};
    return UtEncryptToolMain(2, argv);
}

} // namespace

TEST(CryptionToolMainTest, RejectsMissingCommand)
{
    char app[] = "crypto_tool";
    char *argv[] = {app};

    EXPECT_EQ(UtEncryptToolMain(1, argv), static_cast<int>(CryptionToolRc::PARAM_INVALID));
}

TEST(CryptionToolMainTest, RejectsMissingAndMalformedConfiguration)
{
    {
        ScopedToolConfig config("not-json");
        EXPECT_EQ(RunTool("--unknown"), static_cast<int>(CryptionToolRc::INTERNAL_ERROR));
    }
    {
        ScopedToolConfig config(R"({"algorithm":"AES256_GCM"})");
        EXPECT_EQ(RunTool("--unknown"), static_cast<int>(CryptionToolRc::INTERNAL_ERROR));
    }
}

TEST(CryptionToolMainTest, LoadsConfigurationSetsEnvironmentAndRejectsUnknownCommand)
{
    ScopedToolConfig config(R"({
        "algorithm":"AES256_GCM",
        "keyManagerType":"openbao",
        "thirdKeyManager":{"keyManagerAddr":"https://127.0.0.1:8200"}
    })");

    ASSERT_EQ(RunTool("--unknown"), static_cast<int>(CryptionToolRc::PARAM_INVALID));
    const char *address = std::getenv("BAO_ADDR");
    ASSERT_NE(address, nullptr);
    EXPECT_STREQ(address, "https://127.0.0.1:8200");
}

TEST(CryptionToolMainTest, DispatchesSupportedCommandsAndReportsHandlerFailures)
{
    ScopedToolConfig config(R"({
        "algorithm":"AES256_GCM",
        "keyManagerType":"vault",
        "thirdKeyManager":{"keyManagerAddr":"https://127.0.0.1:8300"}
    })");

    for (const char *command : {"--encrypt", "--removekey", "--displaykey", "--createkey", "--reEncrypt"}) {
        EXPECT_EQ(RunTool(command), static_cast<int>(CryptionToolRc::INTERNAL_ERROR)) << command;
    }
    const char *address = std::getenv("VAULT_ADDR");
    ASSERT_NE(address, nullptr);
    EXPECT_STREQ(address, "https://127.0.0.1:8300");
}

} // namespace cdf::test
