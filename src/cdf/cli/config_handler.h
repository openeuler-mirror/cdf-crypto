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

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

#include "rapidjson/document.h"

#include "cdf/cli/defines.h"

namespace cdf {

struct ThirdKmc {
    std::string kmcPath;
    std::string kmcAddr;
};

struct CliConfig {
    std::string algorithm;
    std::string kmcType;
    ThirdKmc thirdKmc;
    CliConfig()
    {
        algorithm = "AES256_GCM"; // AES256_GCM/CHACHA20_POLY1305
    }
};

CryptionToolRc GetConfig(const std::string &filePath, CliConfig &cfg);

CryptionToolRc CheckConfig(CliConfig &cfg);

} // namespace cdf
