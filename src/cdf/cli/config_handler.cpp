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

#include "cdf/cli/config_handler.h"

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/utils/file_utils.h"

namespace cdf {

namespace {
constexpr const char *CRYPTO_ALGORITHM = "algorithm";
constexpr const char *CRYPTO_3RD_KMC_SCOPE = "thirdKeyManager";
constexpr const char *CRYPTO_3RD_KMC_TYPE = "keyManagerType";
constexpr const char *CRYPTO_3RD_KMC_PATH = "keyManagerPath";
constexpr const char *CRYPTO_3RD_KMC_ADDR = "keyManagerAddr";
constexpr uint32_t MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 * 1024 * 1024: 最大支持文件大小10M

enum class LogLevel {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,   // log level debug
    LOG_LEVEL_INFO = 2,    // log level info
    LOG_LEVEL_WARN = 3,    // log level warn
    LOG_LEVEL_ERROR = 4,   // log level error
    LOG_LEVEL_CRITICAL = 5 // log level critical
};

bool IsAbsolutePath(const std::string &filePath)
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

bool CheckFileAccess(const std::string &path, const int mode)
{
    return access(path.c_str(), mode) != -1;
}

bool CheckFileStat(const std::string &filePath)
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

CryptionToolRc CDFCheckFilePathAndStat(std::string &filePath, const int mode)
{
    if (!IsAbsolutePath(filePath)) {
        CCSEC_LOG_ERROR("|CDFCheckFilePathAndStat|END|returnF||relative path.");
        return CryptionToolRc::INTERNAL_ERROR;
    }

    if (!FileUtils::CanonicalPath(filePath)) {
        CCSEC_LOG_ERROR("|CDFCheckFilePathAndStat|END|returnF||canonical path failed.");
        return CryptionToolRc::INTERNAL_ERROR;
    }
    if (!CheckFileStat(filePath)) {
        CCSEC_LOG_ERROR("|CDFCheckFilePathAndStat|END|returnF||check path stat failed.");
        return CryptionToolRc::INTERNAL_ERROR;
    }
    if (!CheckFileAccess(filePath, mode)) {
        CCSEC_LOG_ERROR("|CDFCheckFilePathAndStat|END|returnF||file path access is not valid.");
        return CryptionToolRc::INTERNAL_ERROR;
    }

    return CryptionToolRc::OK;
}

CryptionToolRc CDFCheckAlg(const std::string &algStr)
{
    if (algStr.empty()) {
        CCSEC_LOG_WARN("|CDFCheckAlg|ENDS|||algStr is not set, use default AES256GCM.");
        return CryptionToolRc::OK;
    }

    std::set<std::string> cryptoAlgorithms = {"AES128_GCM", "AES256_GCM", "SM4_CTR", "AES128_CCM", "CHACHA20_POLY1305"};
    auto it = cryptoAlgorithms.find(algStr);
    if (it != cryptoAlgorithms.end()) {
        return CryptionToolRc::OK;
    }
    CCSEC_LOG_ERROR("|CDFCheckAlg|ENDF|||invalid crypto algorithm");
    return CryptionToolRc::INTERNAL_ERROR;
}

CryptionToolRc CDFCheckType(const std::string &kmcType)
{
    if (kmcType.empty()) {
        CCSEC_LOG_WARN("|CDFCheckType|ENDS|||keyManagerType is not set, use default local KMC.");
        return CryptionToolRc::OK;
    }

    if (kmcType != "openbao" && kmcType != "vault") {
        CCSEC_LOG_ERROR("|CDFCheckType|ENDF|||invalid 3rd keyManagerType");
        return CryptionToolRc::INTERNAL_ERROR;
    }
    return CryptionToolRc::OK;
}

CryptionToolRc CDFCheckPath(std::string &kmcPath)
{
    if (CDFCheckFilePathAndStat(kmcPath, F_OK | R_OK | X_OK) != CryptionToolRc::OK) {
        CCSEC_LOG_ERROR("|CDFCheckType|ENDF|||invalid keyManagerPath: " << kmcPath);
        return CryptionToolRc::INTERNAL_ERROR;
    }
    return CryptionToolRc::OK;
}

rapidjson::Document CDF_ReadConfig(const std::string &filePath)
{
    auto filePathCopy = filePath;
    if (CDFCheckFilePathAndStat(filePathCopy, F_OK | R_OK) != CryptionToolRc::OK) {
        CCSEC_LOG_ERROR("|CDF_ReadConfig|ENDF|||invalid config file: " << filePathCopy);
        return {};
    }
    std::ifstream file(filePathCopy);
    if (!file.is_open()) {
        CCSEC_LOG_ERROR("|CDF_ReadConfig|END|||failed to open config file.");
        return {};
    }

    rapidjson::IStreamWrapper isw(file);
    rapidjson::Document doc;
    doc.ParseStream(isw);
    if (doc.HasParseError()) {
        CCSEC_LOG_ERROR("|CDF_ReadConfig|END|||parse config file failed.");
        return {};
    }

    return doc;
}

} // namespace

CryptionToolRc ConfigKMC(const rapidjson::Document &configDoc, CliConfig &cfg)
{
    if (!configDoc.HasMember(CRYPTO_ALGORITHM)) {
        CCSEC_LOG_WARN("|CDF_GetConfig||||algorithm is null, use default: " << cfg.algorithm);
    } else {
        const rapidjson::Value &algorithm = configDoc[CRYPTO_ALGORITHM];
        if (!algorithm.IsString()) {
            CCSEC_LOG_ERROR("|CDF_GetConfig|END|||algorithm item is invalid");
            return CryptionToolRc::INTERNAL_ERROR;
        }
        cfg.algorithm = algorithm.GetString();
    }

    if (!configDoc.HasMember(CRYPTO_3RD_KMC_TYPE)) {
        CCSEC_LOG_ERROR("|CDF_GetConfig||||type is null");
        return CryptionToolRc::PARAM_INVALID;
    } else {
        const rapidjson::Value &kmcType = configDoc[CRYPTO_3RD_KMC_TYPE];
        if (kmcType.IsString()) {
            cfg.kmcType = kmcType.GetString();
        }
    }

    if (!configDoc.HasMember(CRYPTO_3RD_KMC_SCOPE)) {
        CCSEC_LOG_WARN("|CDF_GetConfig||||3rd kmc is null, use default local kmc.");
    } else {
        const rapidjson::Value &thirdKmc = configDoc[CRYPTO_3RD_KMC_SCOPE];
        if (!thirdKmc.IsObject()) {
            CCSEC_LOG_ERROR("|CDF_GetConfig|END|||3rdKmc item is invalid");
            return CryptionToolRc::INTERNAL_ERROR;
        }

        if (thirdKmc.HasMember(CRYPTO_3RD_KMC_PATH)) {
            const rapidjson::Value &kmcPath = thirdKmc[CRYPTO_3RD_KMC_PATH];
            if (kmcPath.IsString()) {
                cfg.thirdKmc.kmcPath = kmcPath.GetString();
            }
        }

        if (thirdKmc.HasMember(CRYPTO_3RD_KMC_ADDR)) {
            const rapidjson::Value &kmcAddr = thirdKmc[CRYPTO_3RD_KMC_ADDR];
            if (kmcAddr.IsString()) {
                cfg.thirdKmc.kmcAddr = kmcAddr.GetString();
            }
        }
    }
    return CryptionToolRc::OK;
}

inline void ExternalLogFunction(int level, const char *msg)
{
    std::string levelStr;
    switch (level) {
        case static_cast<int>(cdf::LogLevel::LOG_LEVEL_TRACE):
            levelStr = "trace";
            break;
        case static_cast<int>(cdf::LogLevel::LOG_LEVEL_DEBUG):
            levelStr = "debug";
            break;
        case static_cast<int>(cdf::LogLevel::LOG_LEVEL_INFO):
            levelStr = "info";
            break;
        case static_cast<int>(cdf::LogLevel::LOG_LEVEL_WARN):
            levelStr = "warn";
            break;
        case static_cast<int>(cdf::LogLevel::LOG_LEVEL_ERROR):
            levelStr = "error";
            break;
        case static_cast<int>(cdf::LogLevel::LOG_LEVEL_CRITICAL):
            levelStr = "critical";
            break;
        default:
            levelStr = "warn";
    }
    // 获取当前时间
    std::time_t now = std::time(nullptr);
    std::tm *ltm = std::localtime(&now);
    if (ltm == nullptr) {
        std::cout << "time error" << std::endl;
        return;
    }
    // 格式化时间字符串
    char timeBuffer[20];
    std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", ltm);
    // 输出带时间的日志
    std::cout << "[" << timeBuffer << "] [" << levelStr << "] " << msg << std::endl;
}

CryptionToolRc GetConfig(const std::string &filePath, CliConfig &cfg)
{
    rapidjson::Document configDoc = CDF_ReadConfig(filePath);
    if (configDoc.IsNull()) {
        std::cout << "|CDF_GetConfig|END|||get config file failed." << std::endl;
        return CryptionToolRc::INTERNAL_ERROR;
    }
    auto log = cdf::Logger::Instance();
    if (log == nullptr) {
        std::cout << "Failed to set external log" << std::endl;
        return CryptionToolRc::INTERNAL_ERROR;
    }
    if (!log->SetExternalLogFunction(ExternalLogFunction)) {
        std::cout << "Failed to set external log" << std::endl;
        return CryptionToolRc::INTERNAL_ERROR;
    }
    auto ret = ConfigKMC(configDoc, cfg);
    if (ret != CryptionToolRc::OK) {
        return ret;
    }
    CCSEC_LOG_INFO("|CDF_ParseConfig|ENDS|||parse config file successfully.");
    return CryptionToolRc::OK;
}

CryptionToolRc CheckConfig(CliConfig &cfg)
{
    if (CDFCheckAlg(cfg.algorithm) != CryptionToolRc::OK) {
        return CryptionToolRc::INTERNAL_ERROR;
    }

    if (CDFCheckType(cfg.kmcType) != CryptionToolRc::OK) {
        return CryptionToolRc::INTERNAL_ERROR;
    }

    if (cfg.kmcType == "kmc") {
        return CryptionToolRc::OK;
    }

    if (CDFCheckPath(cfg.thirdKmc.kmcPath) != CryptionToolRc::OK) {
        return CryptionToolRc::INTERNAL_ERROR;
    }

    return CryptionToolRc::OK;
}

} // namespace cdf
