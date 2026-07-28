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

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>

#include "gtest/gtest.h"

#include "cdf/utils/file_utils.h"
#include "cdf/utils/str_utils.h"
#include "cdf/utils/time_utils.h"
#include "cdf/base/custom_logger.h"
#include "scoped_environment.h"
namespace cdf::test {

class TestCDFUtils : public ::testing::Test {
public:
    static std::string GetLocalPath();

protected:
    void SetUp() override
    {
        // 创建临时文件
        const mode_t mode0755 = 0755;
        std::ofstream("test_file.txt") << "Test content";
        mkdir("test_dir", mode0755);
        auto ret = symlink("test_file.txt", "test_symlink.txt");
        EXPECT_EQ(ret, 0);
    }

    void TearDown() override
    {
        // 清理临时文件
        unlink("test_file.txt");
        unlink("test_symlink.txt");
        rmdir("test_dir");
    }
};

std::string TestCDFUtils::GetLocalPath(void)
{
    char cwd[PATH_MAX] = {0};
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        std::string fullPath = std::string(cwd);
        return fullPath;
    } else {
        return "";
    }
}

TEST_F(TestCDFUtils, EmptyFilePathTest)
{
    EXPECT_FALSE(FileUtils::IsAbsolutePath(""));
}

TEST_F(TestCDFUtils, NonAbsoluteFilePathTest)
{
    const std::string filePath = "non_absolute";
    EXPECT_FALSE(FileUtils::IsAbsolutePath(filePath));
}

TEST_F(TestCDFUtils, PathWithParentFolderIndicatorTest)
{
    const std::string filePath = "subdir/../../file";
    EXPECT_FALSE(FileUtils::IsAbsolutePath(filePath));
}

TEST_F(TestCDFUtils, IsAbsolutePathAbsoluteFilePathTest)
{
    const std::string filePath = "/path/file";
    EXPECT_TRUE(FileUtils::IsAbsolutePath(filePath));
}

TEST_F(TestCDFUtils, GetFolderPath_NormalPath)
{
    std::string filePath = "/a/b/c/d.txt";
    std::string expectedFolder = "/a/b/c";
    std::string result;

    bool success = FileUtils::GetFolderPath(filePath, result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, expectedFolder);
}

TEST_F(TestCDFUtils, GetFolderPath_NoSlash)
{
    std::string filePath = "d.txt";
    std::string result;

    bool success = FileUtils::GetFolderPath(filePath, result);
    EXPECT_FALSE(success);
}

TEST_F(TestCDFUtils, GetFileName_NormalPath)
{
    std::string filePath = "/a/b/c/d.txt";
    std::string expectedName = "/d.txt";
    std::string result;

    bool success = FileUtils::GetFileName(filePath, result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, expectedName);
}

TEST_F(TestCDFUtils, GetFileName_NoSlash)
{
    std::string filePath = "d.txt";
    std::string result;

    bool success = FileUtils::GetFileName(filePath, result);
    EXPECT_FALSE(success);
}

TEST_F(TestCDFUtils, CheckFileStat_NormalFile)
{
    EXPECT_TRUE(FileUtils::CheckFileStat("test_file.txt"));
}

TEST_F(TestCDFUtils, CheckFileStat_FileNotExist)
{
    EXPECT_FALSE(FileUtils::CheckFileStat("non_existent_file.txt"));
}

TEST_F(TestCDFUtils, IsFileValid_NormalFile)
{
    std::string errMsg;
    EXPECT_TRUE(FileUtils::IsFileValid("test_file.txt", errMsg));
}

TEST_F(TestCDFUtils, IsFileValid_FileNotExist)
{
    std::string errMsg;
    EXPECT_FALSE(FileUtils::IsFileValid("non_existent_file.txt", errMsg));
    bool ret = FileUtils::IsFileValid("***", errMsg);
    EXPECT_FALSE(ret);
    ret = FileUtils::IsFileValid(GetLocalPath(), errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, IsFileValid_ZeroLengthFile)
{
    const std::string emptyFile = "emptyfile.txt";
    FILE *fp = fopen(emptyFile.c_str(), "wb");
    fclose(fp);

    std::string errMsg;
    bool ret = FileUtils::IsFileValid(emptyFile, errMsg);
    EXPECT_TRUE(ret);

    remove(emptyFile.c_str()); // 清理文件
}

TEST_F(TestCDFUtils, RegularFilePath_PathIsEmpty)
{
    std::string baseDir = "temp_test/";
    std::string filePath = "";
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath(filePath, baseDir, errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, RegularFilePath_Symlink)
{
    std::string baseDir = "temp_test/";
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath("test_symlink.txt", baseDir, errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, RegularFilePath_BasePathIsEmpty)
{
    std::string baseDir = "";
    std::string filePath = "temp_test/";
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath(filePath, baseDir, errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, RegularFilePath_ExceedsPathMaxLimitation)
{
    std::string baseDir = "temp_test/";
    std::string longPath(PATH_MAX + 1, 'a');
    longPath += ".tmp";
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath(longPath, baseDir, errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, RegularFilePath_PathNotInBaseDir)
{
    // 初始化临时目录和文件
    std::string tempDir = "temp_test/";
    mkdir(tempDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    std::string validFilePath = tempDir + "test_file.txt";
    FILE *fp = fopen(validFilePath.c_str(), "wb");
    fprintf(fp, "Test Content");
    fclose(fp);
    std::string baseDir = "incorrect_base/";
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath(validFilePath, baseDir, errMsg);
    EXPECT_FALSE(ret);
    remove(validFilePath.c_str());
    rmdir(tempDir.c_str());
}

TEST_F(TestCDFUtils, RegularFilePathNoBase_PathIsEmpty)
{
    std::string filePath = "";
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath(filePath, errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, RegularFilePathNoBase_Symlink)
{
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath("test_symlink.txt", errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, RegularFilePathNoBase_ExceedsPathMaxLimitation)
{
    std::string longPath(PATH_MAX + 1, 'a');
    longPath += ".tmp";
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath(longPath, errMsg);
    EXPECT_FALSE(ret);
}

TEST_F(TestCDFUtils, RegularFilePathNoBase)
{
    // 初始化临时目录和文件
    std::string tempDir = "temp_test/";
    mkdir(tempDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    std::string validFilePath = tempDir + "test_file.txt";
    FILE *fp = fopen(validFilePath.c_str(), "wb");
    fprintf(fp, "Test Content");
    fclose(fp);
    std::string errMsg;
    bool ret = FileUtils::RegularFilePath(validFilePath, errMsg);
    EXPECT_TRUE(ret);
    remove(validFilePath.c_str());
    rmdir(tempDir.c_str());
}

TEST_F(TestCDFUtils, CheckOwner_NormalFile)
{
    std::string errMsg;
    EXPECT_TRUE(FileUtils::CheckOwner("test_file.txt", errMsg));
}

TEST_F(TestCDFUtils, CheckOwner_NotExistFile)
{
    std::string errMsg;
    EXPECT_FALSE(FileUtils::CheckOwner("not_exist_file.txt", errMsg));
}

TEST_F(TestCDFUtils, IsFile_NormalFile)
{
    EXPECT_TRUE(FileUtils::IsFile("test_file.txt"));
}

TEST_F(TestCDFUtils, IsFile_NotExistFile)
{
    EXPECT_FALSE(FileUtils::IsFile("not_exist_file.txt"));
}

TEST_F(TestCDFUtils, CheckPermission)
{
    const std::string testFile = "test_file";
    const mode_t targetMode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IROTH; // 0744
    // 创建文件并授予权限
    int fd = creat(testFile.c_str(), targetMode);
    close(fd);

    std::string errMsg;
    bool result = FileUtils::CheckPermission(testFile, targetMode, false, errMsg);
    remove(testFile.c_str());
    EXPECT_TRUE(result);
    EXPECT_TRUE(errMsg.empty());
}

TEST_F(TestCDFUtils, CheckPermission_Failure)
{
    const std::string testFile = "test_file";
    const mode_t targetMode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IROTH; // 0744
    // 创建文件并授予权限
    int fd = creat(testFile.c_str(), targetMode);
    close(fd);

    std::string errMsg;
    bool result = FileUtils::CheckPermission(testFile, 0600, false, errMsg);
    remove(testFile.c_str());
    EXPECT_FALSE(result);
}

TEST_F(TestCDFUtils, CheckPermission_PermissionsExceedAllowances_CheckFailsForAllCases)
{
    const std::string filePath = "test_file";
    const mode_t targetMode = S_IRWXU | S_IRWXG | S_IRWXO;
    // 创建文件并授予权限
    int fd = creat(filePath.c_str(), targetMode);
    close(fd);

    std::string errMsg;

    // 假设我们只允许 owner 有部分权限，而其他则不能超出规定
    const mode_t allowableMask = S_IRUSR | S_IWUSR; // 仅用户有读写

    bool checkResult = FileUtils::CheckPermission(filePath, allowableMask, false, errMsg);
    EXPECT_FALSE(checkResult);
    remove(filePath.c_str());
}

TEST_F(TestCDFUtils, CheckPermission_GroupOrOtherExecuteWithCurrentUserFlagSet)
{
    const std::string filePath = "test_file1";
    const mode_t targetMode = S_IXOTH;
    // 创建文件并授予权限
    int fd = creat(filePath.c_str(), targetMode);
    close(fd);

    mode_t requestedMode = S_IRUSR; // 仅仅是用户读取
    bool onlyCurrentUserOperation = true;
    std::string errorMsg;
    bool res = FileUtils::CheckPermission(filePath, requestedMode, onlyCurrentUserOperation, errorMsg);
    EXPECT_FALSE(res);
    remove(filePath.c_str());
}

TEST_F(TestCDFUtils, CheckFilePathExist)
{
    std::string tempDir = "temp_test/";
    mkdir(tempDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    bool result = FileUtils::CheckFilePathExist(tempDir, false);
    rmdir(tempDir.c_str());
    EXPECT_TRUE(result);
}

TEST_F(TestCDFUtils, CheckFilePathExist_NotExist)
{
    std::string tempDir = "not_exist_dir/";
    bool result = FileUtils::CheckFilePathExist(tempDir, false);
    EXPECT_FALSE(result);
}

TEST_F(TestCDFUtils, CheckFilePathExist_IllegalPathCharacters)
{
    std::string invalidPath = "/illeg-al? characters";
    bool result = FileUtils::CheckFilePathExist(invalidPath, true);
    EXPECT_FALSE(result);
}

TEST_F(TestCDFUtils, CheckDirectoryExists)
{
    std::string tempDir = "temp_test/";
    mkdir(tempDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    bool result = FileUtils::CheckDirectoryExists(tempDir);
    rmdir(tempDir.c_str());
    EXPECT_TRUE(result);
}

TEST_F(TestCDFUtils, CheckDirectoryExists_NotExist)
{
    std::string tempDir = "not_exist_dir/";
    bool result = FileUtils::CheckDirectoryExists(tempDir);
    EXPECT_FALSE(result);
}

void TestUtcToLocal(const char *utcStr, const char *expectedLocalStr)
{
    ScopedEnvironment timezone("TZ", "Asia/Shanghai");
    const size_t bufferSize = UTCTIME_LEN + 1;
    char buffer[bufferSize]{0};    // 初始化为零，确保初始状态安全
    std::string utcString(utcStr); // 创建string对象存储UTC字符串
    size_t maxChars = std::min(utcString.length(), size_t(bufferSize - 1));
    utcString.resize(maxChars);
    // 将string的内容复制到buffer数组中，并确保结尾空字符的存在
    utcString.copy(buffer, maxChars);
    buffer[maxChars] = '\0'; // 确保最后一个字符为('\0')，即使utcString的大小正好达到maxChars也会安全地添加
    UtcTimeToLocal(buffer, sizeof(buffer));
    EXPECT_STREQ(buffer, expectedLocalStr);
}

TEST_F(TestCDFUtils, UtcTimeToLocal)
{
    const char *utcStr1 = "2024-06-11T12:00:00Z";
    const char *expectedLocalStr1 = "2024/06/11 20:00:00 ";
    TestUtcToLocal(utcStr1, expectedLocalStr1);

    const char *utcStr2 = "2024-06-11T04:00:00Z";
    const char *expectedLocalStr2 = "2024/06/11 12:00:00 ";
    TestUtcToLocal(utcStr2, expectedLocalStr2);

    const char *utcStr3 = "2024-12-31T20:00:00Z";
    const char *expectedLocalStr3 = "2025/01/01 04:00:00 ";
    TestUtcToLocal(utcStr3, expectedLocalStr3);
}

TEST_F(TestCDFUtils, GetPathBeforeLastPart_normal)
{
    std::string path = "/tmp_dir/test";
    std::string expected = "/tmp_dir";
    std::string actual = FileUtils::GetPathBeforeLastPart(path);
    EXPECT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TestCDFUtils, GetPathBeforeLastPart_no_slash)
{
    std::string path = "testfile";
    std::string expected = "";
    std::string actual = FileUtils::GetPathBeforeLastPart(path);
    EXPECT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TestCDFUtils, GetPathBeforeLastPart_single_slash)
{
    std::string path = "/";
    std::string expected = "";
    std::string actual = FileUtils::GetPathBeforeLastPart(path);
    EXPECT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TestCDFUtils, GetPathBeforeLastPart_ends_with_slash)
{
    std::string path = "/tmp_dir/directory/";
    std::string expected = "/tmp_dir/directory";
    std::string actual = FileUtils::GetPathBeforeLastPart(path);
    EXPECT_STREQ(expected.c_str(), actual.c_str());
}

TEST_F(TestCDFUtils, IsEndWith_positive_case)
{
    std::string str = "hello_world_final";
    std::string suffix = "_final";
    bool result = FileUtils::IsEndWith(str, suffix);
    EXPECT_TRUE(result);
}

TEST_F(TestCDFUtils, IsEndWith_negative_case)
{
    std::string str = "test_beginning";
    std::string suffix = "begin";
    bool result = FileUtils::IsEndWith(str, suffix);
    EXPECT_FALSE(result);
}

TEST_F(TestCDFUtils, IsEndWith_same_strings)
{
    std::string str = "abcdef";
    std::string suffix = "abcdef";
    bool result = FileUtils::IsEndWith(str, suffix);
    EXPECT_TRUE(result);
}

TEST_F(TestCDFUtils, IsEndWith_empty_strings)
{
    std::string str = "";
    std::string suffix = "";
    bool result = FileUtils::IsEndWith(str, suffix);
    EXPECT_FALSE(result);
}

TEST_F(TestCDFUtils, IsEndWith_one_char_suffix)
{
    std::string str = "helloworld";
    std::string suffix = "d";
    bool result = FileUtils::IsEndWith(str, suffix);
    EXPECT_TRUE(result);
}

TEST_F(TestCDFUtils, StrToLong_PositiveNumberConversion)
{
    const std::string input = "12345";
    long expected = 12345;
    long result = 0;

    bool success = StrUtils::StrToLong(input, result);
    EXPECT_TRUE(success);
    EXPECT_EQ(expected, result);
}

// Additional tests for time_utils boundary conditions
TEST_F(TestCDFUtils, UtcTimeToLocal_NullPointer)
{
    // Test null pointer handling
    uint32_t ret = UtcTimeToLocal(nullptr, 0);
    EXPECT_EQ(ret, 1u);
}

TEST_F(TestCDFUtils, UtcTimeToLocal_InvalidFormat)
{
    // Test invalid format handling
    char buffer[] = "invalid_time_format";
    uint32_t ret = UtcTimeToLocal(buffer, sizeof(buffer));
    EXPECT_EQ(ret, 1u);
}

TEST_F(TestCDFUtils, UtcTimeToLocal_CrossMonth)
{
    ScopedEnvironment timezone("TZ", "Asia/Shanghai");
    char leapDay[UTCTIME_LEN + 1] = "2024-02-29T16:00:00Z";

    ASSERT_EQ(UtcTimeToLocal(leapDay, sizeof(leapDay)), 0u);
    EXPECT_STREQ(leapDay, "2024/03/01 00:00:00 ");
}

TEST_F(TestCDFUtils, UtcTimeToLocal_CrossYear)
{
    ScopedEnvironment timezone("TZ", "Asia/Shanghai");
    char yearEnd[UTCTIME_LEN + 1] = "2024-12-31T16:00:00Z";

    ASSERT_EQ(UtcTimeToLocal(yearEnd, sizeof(yearEnd)), 0u);
    EXPECT_STREQ(yearEnd, "2025/01/01 00:00:00 ");
}

} // namespace cdf::test
