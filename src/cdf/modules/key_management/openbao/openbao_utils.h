// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
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

#include <unistd.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "cdf/modules/key_management/define.h"

namespace cdf {

// Get the decoded key from a json string
std::string GetJsonFieldAsStr(const std::string &jsonStr);

// Get the decoded key from a json string
KeyManagerRC GetJsonFieldIntPairVec(const std::string &jsonStr, std::vector<std::pair<uint32_t, uint32_t>> &out);

int GetJsonFieldMaxInt(const std::string &jsonStr);

// Run commands and check results. It's okay to leave accessToken as empty, in that case, this function simply run the
// cmdVec and check the results. If result string contains value "ERROR", this function returns
// KeyManagerRC::ERROR, otherwise returns KeyManagerRC::OK
KeyManagerRC RunCommandAndCheck(std::string_view exePath, std::string_view accessToken, std::string_view cmdArgs);

std::pair<KeyManagerRC, std::string> RunCommandAndGetResult(std::string_view exePath, std::string_view accessToken,
                                                            std::string_view cmdArgs);

} // namespace cdf
