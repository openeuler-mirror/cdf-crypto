// Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
// Confidential Data defensive Framework is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#pragma once

#include <sys/stat.h>

#include <climits>
#include <string>
#include <utility>

namespace cdf {

class FileUtils {
public:
    /**
     * judge file exists
     * @param path: file full path
     * @param pattern: regex pattern
     */
    static bool CheckFileExists(const std::string &filePath);

    /**
     * is directory exists.
     * @param dir directory
     * @return
     */
    static bool CheckDirectoryExists(const std::string &dirPath);

    /**
     * Check whether the destination path is a link
     * @param filePath raw file path
     * @return
     */
    static bool IsSymlink(const std::string &filePath);

    /**
     * Regular the file path using realPath.
     * @param filePath raw file path
     * @param baseDir file path must in base dir
     * @param errMsg the err msg
     * @return
     */
    static bool RegularFilePath(const std::string &filePath, const std::string &baseDir, std::string &errMsg);

    /**
     * Regular the file path using realPath.
     * @param filePath raw file path
     * @param errMsg the err msg
     * @return
     */
    static bool RegularFilePath(const std::string &filePath, std::string &errMsg);

    /**
     * Check the existence of the file and the size of the file.
     * @param configFile the input file path
     * @param errMsg the err msg
     * @return
     */
    static bool IsFileValid(const std::string &configFile, std::string &errMsg);

    /**
     * Check if the current user owns the file
     * @param filePath
     * @param errMsg the err msg
     * @return
     */
    static bool CheckOwner(const std::string &filePath, std::string &errMsg);

    /**
     * Check if the file permission exceeds the given permission in mode
     * @param filePath
     * @param mode
     * @param onlyCurrentUseOp
     * @param errMsg the err msg
     * @return
     */
    static bool CheckPermission(const std::string &filePath, const mode_t &mode, bool onlyCurrentUserOp,
                                std::string &errMsg);

    /**
     * Check if the current user have access (w.r.t. mode)
     * @param filePath
     * @param mode
     * @return
     */
    static bool CheckUserAccess(const std::string &filePath, int mode);

    static bool CheckFilePathExist(std::string &filePath, bool isFile = true);

    static std::string GetPathBeforeLastPart(const std::string &path);

    static bool IsEndWith(const std::string &str, const std::string &suffix);

    static bool IsFile(const std::string &path);

    /* additional apis */
    static bool CanonicalPath(std::string &path);
    static std::pair<bool, std::string> CanonicalPath(const std::string &path);

    static bool Exist(const std::string &path, const int &mode = 0);
    static bool CheckFileStat(const std::string &filePath);
    static bool GetFolderPath(const std::string &filePath, std::string &folderPath);
    static bool GetFileName(const std::string &filePath, std::string &fileName);
    static bool IsAbsolutePath(const std::string &filePath);

    static bool CheckFileSuffix(const std::string &ksf, const std::string &suffix);
};

} // namespace cdf
