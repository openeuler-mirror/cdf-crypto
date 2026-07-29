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

#ifndef CDF_CMD_H
#define CDF_CMD_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cdf/cli/config_handler.h"
#include "cdf/cli/defines.h"

namespace cdf {
class Cmd {
public:
    /* *
     * @brief handle the command
     * @param cmdParams param of command
     * @return the result @CryptionToolRc
     */
    virtual CryptionToolRc HandleCmd(std::vector<std::string> &cmdParams, const CliConfig &config) = 0;
};

class CmdManager {
public:
    /* *
     * @brief Initialize CmdManager
     * @return CryptionToolRc::OK success, otherwise failed
     */
    CryptionToolRc Initialize();

    /* *
     * @brief get handle by cmd
     * @param cmd the cmd
     * @return the handle selected by cmd
     */
    std::shared_ptr<Cmd> GetHandler(const std::string &cmd);

private:
    std::map<std::string, std::shared_ptr<Cmd>> handlers;
};
} // namespace cdf

#endif // CDF_CMD_H
