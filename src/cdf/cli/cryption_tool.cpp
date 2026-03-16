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
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"
#include "cdf/cli/cmd.h"
#include "cdf/cli/config_handler.h"
#include "cdf/cli/defines.h"
#include "cdf/cli/kmc_cmd.h"
#include "cdf/base/custom_logger.h"

static const int MIN_PARAM_COUNT = 2;
static const int PARAM_CMD_TYPE_IDX = 1;
static const int PARAM_CMD_INPUT_START_IDX = 2;

namespace cdf {

inline CryptionToolRc ParseArgv(const std::vector<std::string> &args, std::string &cmd,
                                std::vector<std::string> &cmdParams)
{
    if (args.size() < MIN_PARAM_COUNT) {
        return cdf::CryptionToolRc::PARAM_INVALID;
    }
    cmd = args[PARAM_CMD_TYPE_IDX];
    auto cmdParamCount = args.size();
    for (size_t index = static_cast<size_t>(PARAM_CMD_INPUT_START_IDX); index < cmdParamCount; ++index) {
        cmdParams.emplace_back(args[index]);
    }
    return cdf::CryptionToolRc::OK;
}

inline std::string GetEventByCommand(const std::string &command)
{
    if (command == "--encrypt") {
        return "Encrypt key ";
    } else if (command == "--secureEraseAllKeystore") {
        return "Remove keystore ";
    } else if (command == "--updateRootKey") {
        return "Update root key";
    } else if (command == "--removekey") {
        return "Remove Key ";
    } else if (command == "--displaykey") {
        return "Display key ";
    } else if (command == "--createkey") {
        return "Createkey key ";
    } else if (command == "--reEncrypt") {
        return "ReEncrypt key ";
    } else {
        return "Unknown command ";
    }
}

inline void SetConfigEnv(const cdf::CliConfig &config)
{
    if (config.kmcType == "openbao") {
        setenv("BAO_ADDR", config.thirdKmc.kmcAddr.c_str(), 1); // 1 = override
    }

    if (config.kmcType == "vault") {
        setenv("VAULT_ADDR", config.thirdKmc.kmcAddr.c_str(), 1); // 1 = override
    }
}
} // namespace cdf

#ifdef __UNIT_TEST__
int UtEncryptToolMain(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    std::string cmd;
    std::vector<std::string> cmdParams;
    std::vector<std::string> args(argv, argv + argc);
    auto ret = cdf::ParseArgv(args, cmd, cmdParams);
    if (ret != cdf::CryptionToolRc::OK) {
        std::cout << cdf::KmcCmd::PARAMETER_ERROR_INFO << std::endl;
        return static_cast<int32_t>(ret);
    }
    auto cmdManager = std::make_shared<cdf::CmdManager>();
    if (cmdManager == nullptr) {
        std::cout << "Failed to create KMC command manager, cause by not enough memory." << std::endl;
        return static_cast<int32_t>(cdf::CryptionToolRc::INTERNAL_ERROR);
    }

    // step 1: read config from file
    std::string configFolder;
    if (cdf::GetBinaryConfigPath(configFolder) != cdf::CryptionToolRc::OK) {
        std::cout << "Failed to find config file" << std::endl;
        return static_cast<int32_t>(cdf::CryptionToolRc::INTERNAL_ERROR);
    }

    configFolder += "/crypto_tool_config.json";

    cdf::CliConfig config;
    auto rc = cdf::GetConfig(configFolder, config);
    if (rc != cdf::CryptionToolRc::OK) {
        std::cout << "Failed to load config file from " << configFolder << std::endl;
        return static_cast<int32_t>(cdf::CryptionToolRc::INTERNAL_ERROR);
    }
    std::cout << "Load config file success" << std::endl;

    SetConfigEnv(config);
    // step2: initialize the cmd manager
    ret = cmdManager->Initialize();
    if (ret != cdf::CryptionToolRc::OK) {
        std::cout << "Failed to Initialize KMC command manager, ret:" << static_cast<int32_t>(ret) << std::endl;
        return static_cast<int32_t>(cdf::CryptionToolRc::INTERNAL_ERROR);
    }

    // step3: calling the right handler
    auto handler = cmdManager->GetHandler(cmd);
    if (handler == nullptr) {
        std::cout << cdf::KmcCmd::PARAMETER_ERROR_INFO << std::endl;
        return static_cast<int32_t>(cdf::CryptionToolRc::PARAM_INVALID);
    }

    // step4: process the actual command
    CCSEC_LOG_DEBUG("|handle command||||start to " << cmd.substr(cdf::NUM_2));

    ret = handler->HandleCmd(cmdParams, config);
    if (ret != cdf::CryptionToolRc::OK) {
        std::cout << "Failed to handle command." << cdf::GetEventByCommand(cmd) << std::endl;
        return static_cast<int32_t>(cdf::CryptionToolRc::INTERNAL_ERROR);
    }

    std::cout << "success to handle command." << std::endl;
    return static_cast<int32_t>(cdf::CryptionToolRc::OK);
}
