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

#include "cdf/utils/file_utils.h"

// clang-format off
#include <unistd.h>
#include <linux/limits.h>
// clang-format on

#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"
#include "cdf/base/custom_logger.h"

namespace cdf {

namespace {
constexpr int64_t MIN_MALLOC_SIZE = 1;
constexpr int64_t DEFAULT_MAX_DATA_SIZE = 4294967296; // uint32_t max
constexpr int PER_PERMISSION_MASK_RWX = 0b111;
constexpr uint32_t MAX_FILE_SIZE = 1024 * 1024; // 1024 * 1024: 文件支持1M文件

size_t GetFileSize(const std::string &filePath)
{
    if (!FileUtils::CheckFileExists(filePath)) {
        CCSEC_LOG_ERROR("|check file path|END|returnF|path is: " << filePath << "|File does not exist.");
        return 0;
    }
    std::string baseDir = "/";
    std::string errMsg;
    if (!FileUtils::RegularFilePath(filePath, baseDir, errMsg)) {
        CCSEC_LOG_ERROR("|regular file|END|returnF||Regular file failed by " << errMsg);
        return 0;
    }

    FILE *fp = fopen(filePath.c_str(), "rb");
    if (fp == nullptr) {
        CCSEC_LOG_ERROR("|open file|END|returnF|path is: " << filePath.c_str() << "|Failed to open file.");
        return 0;
    }
    auto ret = fseek(fp, 0, SEEK_END);
    if (ret != 0) {
        CCSEC_LOG_ERROR("|seek to end of file|END|returnF||Error seeking to end of file, ret is: " << ret);
        fclose(fp);
        return 0;
    }
    auto fileSize = static_cast<size_t>(ftell(fp));
    ret = fseek(fp, 0, SEEK_SET);
    if (ret != 0) {
        CCSEC_LOG_ERROR("|seek to set of file|END|returnF||Error seeking to set of file, ret is:" << ret);
        fclose(fp);
        return 0;
    }
    if (fclose(fp) != 0) {
        CCSEC_LOG_ERROR("|close file||||Closing file failed.");
    }
    return fileSize;
}

inline bool CheckDataSize(int64_t size)
{
    return !(size > DEFAULT_MAX_DATA_SIZE || size < MIN_MALLOC_SIZE);
}
} // namespace

bool FileUtils::CheckFileExists(const std::string &filePath)
{
    struct stat buffer;
    return (stat(filePath.c_str(), &buffer) == 0);
}

bool FileUtils::CheckDirectoryExists(const std::string &dirPath)
{
    struct stat buffer;
    if (stat(dirPath.c_str(), &buffer) != 0) {
        return false;
    }
    return (S_ISDIR(buffer.st_mode) == 1);
}

bool FileUtils::IsSymlink(const std::string &filePath)
{
    struct stat buf;
    if (lstat(filePath.c_str(), &buf) != 0) {
        return false;
    }
    return S_ISLNK(buf.st_mode);
}

bool FileUtils::RegularFilePath(const std::string &filePath, const std::string &baseDir, std::string &errMsg)
{
    if (filePath.empty()) {
        errMsg = "The file path is empty.";
        return false;
    }
    if (baseDir.empty()) {
        errMsg = "The file path basedir is empty.";
        return false;
    }
    if (filePath.size() > PATH_MAX) {
        errMsg = "The file path exceeds the maximum value set by PATH_MAX.";
        return false;
    }
    if (IsSymlink(filePath)) {
        errMsg = "The file is a link.";
        return false;
    }
    std::array<char, PATH_MAX + 1> path = {0x00};
    char *ret = realpath(filePath.c_str(), path.data());
    if (ret == nullptr) {
        errMsg = "The path realpath parsing failed.";
        return false;
    }
    std::string realFilePath(path.begin(), path.end());

    std::string dir = baseDir.back() == '/' ? baseDir : baseDir + "/";
    if (realFilePath.rfind(dir, 0) != 0) {
        errMsg = "The file is invalid, it's not in baseDir directory.";
        return false;
    }

    return true;
}

bool FileUtils::RegularFilePath(const std::string &filePath, std::string &errMsg)
{
    if (filePath.empty()) {
        errMsg = "The file path is empty.";
        return false;
    }

    if (filePath.size() > PATH_MAX) {
        errMsg = "The file path exceeds the maximum value set by PATH_MAX.";
        return false;
    }
    if (IsSymlink(filePath)) {
        errMsg = "The file is a link.";
        return false;
    }
    std::array<char, PATH_MAX + 1> path = {0x00};
    char *ret = realpath(filePath.c_str(), path.data());
    if (ret == nullptr) {
        errMsg = "The path realpath parsing failed.";
        return false;
    }
    return true;
}

bool FileUtils::CheckOwner(const std::string &filePath, std::string &errMsg)
{
    struct stat buf;
    int ret = stat(filePath.c_str(), &buf);
    if (ret != 0) {
        errMsg = "Get file stat failed.";
        return false;
    }
    if (buf.st_uid != getuid()) {
        errMsg = "owner id diff: current process user id is " + std::to_string(getuid()) + ", file owner id is " +
                 std::to_string(buf.st_uid);
        return false;
    }
    return true;
}

bool FileUtils::IsFileValid(const std::string &configFile, std::string &errMsg)
{
    struct stat buffer{};
    if (stat(configFile.c_str(), &buffer) != 0) {
        errMsg = "The input file is not a regular file or not exists";
        return false;
    }
    if (S_ISDIR(buffer.st_mode)) {
        errMsg = "The input path is a directory, not a regular file";
        return false;
    }
    size_t fileSize = GetFileSize(configFile);
    if (fileSize == 0) {
        errMsg = "The input file is empty";
    } else if (!CheckDataSize(fileSize)) {
        errMsg = "Read input file failed, file is too large";
        return false;
    }
    return true;
}

bool FileUtils::CheckPermission(const std::string &filePath, const mode_t &mode, bool onlyCurrentUserOp,
                                std::string &errMsg)
{
    struct stat buf;
    int ret = stat(filePath.c_str(), &buf);
    if (ret != 0) {
        errMsg = "Get file stat failed.";
        return false;
    }

    mode_t mask = PER_PERMISSION_MASK_RWX;
    const int perPermWidth = 3;
    std::vector<std::string> permMsg = {"Other group permission", "Owner group permission", "Owner permission"};
    for (int i = perPermWidth; i > 0; i--) {
        uint32_t curPerm = (buf.st_mode & (mask << ((i - 1) * perPermWidth))) >> ((i - 1) * perPermWidth);
        uint32_t maxPerm = (mode & (mask << ((i - 1) * perPermWidth))) >> ((i - 1) * perPermWidth);
        if ((curPerm | maxPerm) != maxPerm) {
            errMsg = " Check " + permMsg[i - 1] + " failed: Current permission is " + std::to_string(curPerm) +
                     ", but required no greater than " + std::to_string(maxPerm) + ".";

            return false;
        }
        uint32_t readPerm = 4; // Read Perm
        uint32_t noPerm = 0;   // No Perm
        if (i != perPermWidth && curPerm != noPerm && curPerm != readPerm) {
            errMsg = " Check " + permMsg[i - 1] + " failed: Current permission is " + std::to_string(curPerm) +
                     ", but required no write or execute permission.";
            if (onlyCurrentUserOp) {
                return false;
            }
        }
    }
    return true;
}

bool FileUtils::CheckFilePathExist(std::string &filePath, bool isFile)
{
    if (!FileUtils::CanonicalPath(filePath)) {
        CCSEC_LOG_WARN("|FileUtils::CheckFilePathExist|returnF| Invalid or "
                       "nont-existing file path: " << filePath);
        return false;
    }
    if (isFile && !CheckFileStat(filePath)) {
        CCSEC_LOG_WARN("|FileUtils::CheckFilePathExist|returnF|Check file "
                       "stats failed, file path: " << filePath);
        return false;
    }
    if (!Exist(filePath, F_OK | R_OK)) {
        CCSEC_LOG_WARN("|FileUtils::CheckFilePathExist|returnF|Read file "
                       "got access denied, file path: " << filePath);
        return false;
    }
    return true;
}

std::string FileUtils::GetPathBeforeLastPart(const std::string &path)
{
    if (path.empty()) {
        return "";
    }
    size_t lastSlashPos = path.find_last_of('/');
    if (lastSlashPos == std::string::npos || (lastSlashPos == 0 && path.size() == 1)) {
        return "";
    }
    return path.substr(0, lastSlashPos);
}

bool FileUtils::IsEndWith(const std::string &str, const std::string &suffix)
{
    if (str.empty() || suffix.empty()) {
        return false;
    }
    if (suffix.size() > str.size()) {
        return false;
    }
    return str.rfind(suffix) == (str.size() - suffix.size());
}

bool FileUtils::IsFile(const std::string &path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0 || !((st.st_mode & S_IFREG) == S_IFREG)) {
        // 如果stat失败，返回false
        auto placeholder = false;
        return placeholder;
    }
    return true;
}

bool FileUtils::Exist(const std::string &path, const int &mode)
{
    return access(path.c_str(), mode) != -1;
}

bool FileUtils::CanonicalPath(std::string &path)
{
    if (path.empty() || path.size() > PATH_MAX) {
        return false;
    }

    /* It will allocate memory to store path */
    char *realPath = realpath(path.c_str(), nullptr);
    if (realPath == nullptr) {
        return false;
    }

    path = realPath; // string copy here

    /* free */
    free(realPath);
    realPath = nullptr;
    return true;
}

std::pair<bool, std::string> FileUtils::CanonicalPath(const std::string &path)
{
    auto copy = path;
    return {CanonicalPath(copy), copy};
}

bool FileUtils::CheckFileStat(const std::string &filePath)
{
    struct stat st;
    if (stat(filePath.c_str(), &st) != 0) {
        return false;
    }

    if ((st.st_mode & S_IFMT) != S_IFREG || st.st_size > MAX_FILE_SIZE) {
        return false;
    }

    return true;
}

bool FileUtils::GetFolderPath(const std::string &filePath, std::string &folderPath)
{
    const size_t pos = filePath.find_last_of('/');
    if (pos == std::string::npos) {
        return false;
    }
    folderPath = filePath.substr(0, pos);
    return true;
}

bool FileUtils::GetFileName(const std::string &filePath, std::string &fileName)
{
    const size_t pos = filePath.find_last_of('/');
    if (pos == std::string::npos) {
        return false;
    }
    fileName = filePath.substr(pos);
    return true;
}

bool FileUtils::IsAbsolutePath(const std::string &filePath)
{
    if (filePath.length() == 0) {
        return false;
    }

    if (filePath[0] != '/') {
        return false;
    }

    if (strstr(filePath.c_str(), "/../") != nullptr || strstr(filePath.c_str(), "/./") != nullptr) {
        return false;
    }

    return true;
}

bool FileUtils::CheckFileSuffix(const std::string &ksf, const std::string &suffix)
{
    std::string copy(ksf);
    if (!FileUtils::IsEndWith(copy, suffix)) {
        CCSEC_LOG_ERROR("|KmKeyManager|returnF|file name error, full file name: \""
            << copy << "\", (file name should end with: \"" << suffix << "\")");
        return false;
    }
    std::string path = FileUtils::GetPathBeforeLastPart(copy);
    if (!FileUtils::CheckFilePathExist(path, false)) {
        CCSEC_LOG_ERROR("|KmKeyManager|returnF|file path does not exist, path: \"" << path << "\"");
        return false;
    }
    return true;
}

bool FileUtils::CheckUserAccess(const std::string &filePath, int mode)
{
    return access(filePath.c_str(), mode) != -1;
}

} // namespace cdf
