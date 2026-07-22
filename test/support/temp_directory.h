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

#ifndef CDF_TEST_TEMP_DIRECTORY_H
#define CDF_TEST_TEMP_DIRECTORY_H

#include <cstdlib>
#include <filesystem>
#include <stdexcept>

namespace cdf::test {

class TempDirectory {
public:
    TempDirectory()
    {
        char path[] = "/tmp/cdf-test-XXXXXX";
        char *created = mkdtemp(path);
        if (created == nullptr) {
            throw std::runtime_error("failed to create temporary directory");
        }
        path_ = created;
    }

    ~TempDirectory()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    TempDirectory(const TempDirectory &) = delete;
    TempDirectory &operator=(const TempDirectory &) = delete;
    TempDirectory(TempDirectory &&) = delete;
    TempDirectory &operator=(TempDirectory &&) = delete;

    const std::filesystem::path &Path() const
    {
        return path_;
    }

private:
    std::filesystem::path path_;
};

} // namespace cdf::test

#endif // CDF_TEST_TEMP_DIRECTORY_H
