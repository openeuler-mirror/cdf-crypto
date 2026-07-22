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

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "cdf/cli/kmc_cmd.h"
#include "temp_directory.h"

namespace cdf {
bool IsLinkFileOrDir(const std::string &path);
uint64_t GetFileLength(const std::string &path);
CryptionToolRc ReadFile(const std::string &path, char *content, uint32_t contentLength);
CryptionToolRc WriteFile(const std::string &path, const std::string &content);
}

namespace cdf::test {
namespace {

class TestableKmcCmd : public KmcCmd {
public:
    using KmcCmd::GetPassFromInput;
    using KmcCmd::ParseDomainId;
    using KmcCmd::ParseDomainIdAndDomainCount;
    using KmcCmd::ReadEncryptContent;
};

class ScopedInput {
public:
    explicit ScopedInput(const std::string &text) : input_(text), old_(std::cin.rdbuf(input_.rdbuf())) {}
    ~ScopedInput()
    {
        std::cin.rdbuf(old_);
        std::cin.clear();
    }

private:
    std::istringstream input_;
    std::streambuf *old_;
};

std::string ReadText(const std::filesystem::path &path)
{
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

} // namespace

TEST(KmcCmdDomainTest, AcceptsFirstDomainInSingleDomainSet)
{
    TestableKmcCmd command;
    uint32_t domainId = 99;

    EXPECT_EQ(command.ParseDomainId("0", 1, domainId), CryptionToolRc::OK);
    EXPECT_EQ(domainId, 0u);
}

TEST(KmcCmdDomainTest, RejectsInvalidDomainIds)
{
    TestableKmcCmd command;
    for (const auto &testCase : std::vector<std::pair<std::string, uint32_t>>{{"invalid", 2}, {"2", 2}}) {
        uint32_t domainId = 0;
        EXPECT_EQ(command.ParseDomainId(testCase.first, testCase.second, domainId), CryptionToolRc::PARAM_INVALID);
    }
}

TEST(KmcCmdDomainTest, ParsesDomainAndCountTogether)
{
    TestableKmcCmd command;
    std::vector<std::string> valid{"1", "2"};
    uint32_t domainId = 0;
    uint32_t domainCount = 0;
    ASSERT_EQ(command.ParseDomainIdAndDomainCount(valid, domainId, domainCount), CryptionToolRc::OK);
    EXPECT_EQ(domainId, 1u);
    EXPECT_EQ(domainCount, 2u);

    std::vector<std::string> invalidCount{"0", "invalid"};
    EXPECT_EQ(command.ParseDomainIdAndDomainCount(invalidCount, domainId, domainCount),
        CryptionToolRc::PARAM_INVALID);
}

TEST(KmcCmdFileTest, DetectsRegularFilesAndSymbolicLinks)
{
    TempDirectory temp;
    auto regular = temp.Path() / "regular";
    auto link = temp.Path() / "link";
    std::ofstream(regular) << "abc";
    std::filesystem::create_symlink(regular, link);

    EXPECT_FALSE(IsLinkFileOrDir(regular.string()));
    EXPECT_TRUE(IsLinkFileOrDir(link.string()));
}

TEST(KmcCmdFileTest, ReportsMissingAndExistingFileLengths)
{
    TempDirectory temp;
    auto file = temp.Path() / "three-bytes";
    std::ofstream(file) << "abc";

    EXPECT_EQ(GetFileLength(file.string()), 3u);
    EXPECT_EQ(GetFileLength((temp.Path() / "missing").string()), static_cast<uint64_t>(-1));
}

TEST(KmcCmdFileTest, ReadsOnlyWhenBufferIncludesTerminatorSpace)
{
    TempDirectory temp;
    auto file = temp.Path() / "content";
    std::ofstream(file) << "abc";
    char exact[4] = {};
    char shortBuffer[3] = {};

    ASSERT_EQ(ReadFile(file.string(), exact, sizeof(exact)), CryptionToolRc::OK);
    EXPECT_STREQ(exact, "abc");
    EXPECT_EQ(ReadFile(file.string(), shortBuffer, sizeof(shortBuffer)), CryptionToolRc::PARAM_INVALID);
    EXPECT_EQ(ReadFile(file.string(), nullptr, sizeof(exact)), CryptionToolRc::PARAM_INVALID);
}

TEST(KmcCmdFileTest, WritesRegularAndSymbolicLinkDestinations)
{
    TempDirectory temp;
    auto target = temp.Path() / "target";
    auto link = temp.Path() / "link";
    std::ofstream(target) << "old";
    std::filesystem::create_symlink(target, link);

    ASSERT_EQ(WriteFile(target.string(), "regular"), CryptionToolRc::OK);
    EXPECT_EQ(ReadText(target), "regular");
    ASSERT_EQ(WriteFile(link.string(), "through-link"), CryptionToolRc::OK);
    EXPECT_EQ(ReadText(target), "through-link");
}

TEST(KmcCmdInputTest, RejectsEmptyAndOverlongPasswords)
{
    TestableKmcCmd command;
    char password[8] = {'x'};
    {
        ScopedInput input("\n");
        EXPECT_EQ(command.GetPassFromInput(password, sizeof(password), true), CryptionToolRc::PARAM_INVALID);
        EXPECT_EQ(password[0], '\0');
    }
    {
        ScopedInput input("1234567\n");
        EXPECT_EQ(command.GetPassFromInput(password, sizeof(password), true), CryptionToolRc::PARAM_INVALID);
    }
}

TEST(KmcCmdInputTest, ReadsMatchingPasswordsAndClearsConfirmation)
{
    TestableKmcCmd command;
    char password[8] = {};
    char confirmation[8] = {};
    ScopedInput input("secret\nsecret\n");

    ASSERT_EQ(command.ReadEncryptContent(password, confirmation, sizeof(password)), CryptionToolRc::OK);
    EXPECT_STREQ(password, "secret");
    for (char value : confirmation) {
        EXPECT_EQ(value, '\0');
    }
}

TEST(KmcCmdInputTest, ClearsBothBuffersWhenPasswordsDiffer)
{
    TestableKmcCmd command;
    char password[8] = {};
    char confirmation[8] = {};
    ScopedInput input("first\nsecond\n");

    EXPECT_EQ(command.ReadEncryptContent(password, confirmation, sizeof(password)), CryptionToolRc::PARAM_INVALID);
    for (char value : password) {
        EXPECT_EQ(value, '\0');
    }
    for (char value : confirmation) {
        EXPECT_EQ(value, '\0');
    }
}

TEST(KmcCmdHandlerTest, RejectsWrongParameterCounts)
{
    CliConfig config;
    std::vector<std::unique_ptr<Cmd>> commands;
    commands.emplace_back(std::make_unique<EncryptKeyCmd>());
    commands.emplace_back(std::make_unique<ReEncryptCmd>());
    commands.emplace_back(std::make_unique<CreateKeyCmd>());
    commands.emplace_back(std::make_unique<DisplaykeyCmd>());
    commands.emplace_back(std::make_unique<RemovekeyCmd>());

    for (const auto &command : commands) {
        std::vector<std::string> parameters;
        EXPECT_EQ(command->HandleCmd(parameters, config), CryptionToolRc::PARAM_INVALID);
    }
}

TEST(KmcCmdHandlerTest, RejectsInvalidAndOutOfRangeDomains)
{
    CliConfig config;
    std::vector<std::unique_ptr<Cmd>> commands;
    commands.emplace_back(std::make_unique<EncryptKeyCmd>());
    commands.emplace_back(std::make_unique<ReEncryptCmd>());
    commands.emplace_back(std::make_unique<CreateKeyCmd>());
    commands.emplace_back(std::make_unique<DisplaykeyCmd>());

    for (const auto &command : commands) {
        std::vector<std::string> invalid{"invalid", "2"};
        EXPECT_EQ(command->HandleCmd(invalid, config), CryptionToolRc::PARAM_INVALID);
        std::vector<std::string> outOfRange{"2", "2"};
        EXPECT_EQ(command->HandleCmd(outOfRange, config), CryptionToolRc::PARAM_INVALID);
    }

    RemovekeyCmd remove;
    std::vector<std::string> invalidDomain{"invalid", "2", "1"};
    EXPECT_EQ(remove.HandleCmd(invalidDomain, config), CryptionToolRc::PARAM_INVALID);
    std::vector<std::string> outOfRangeDomain{"2", "2", "1"};
    EXPECT_EQ(remove.HandleCmd(outOfRangeDomain, config), CryptionToolRc::PARAM_INVALID);
}

TEST(KmcCmdHandlerTest, RejectsInvalidRemoveKeyId)
{
    RemovekeyCmd command;
    CliConfig config;
    std::vector<std::string> parameters{"0", "2", "invalid"};

    EXPECT_EQ(command.HandleCmd(parameters, config), CryptionToolRc::PARAM_INVALID);
}

} // namespace cdf::test
