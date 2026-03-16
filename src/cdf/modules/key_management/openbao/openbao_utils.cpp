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

#include "cdf/modules/key_management/openbao/openbao_utils.h"

#include <sys/wait.h>

#include <cstring>
#include <exception>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "rapidjson/document.h"
#include "securec/securec.h"

#include "cdf/base/ccsec_logger.h"
#include "cdf/base/common_define.h"
#include "cdf/utils/str_utils.h"

namespace cdf {

using PipeTy = std::array<int, NUM_2>;

namespace {

constexpr std::string_view VAULT_LIST_EMPTY_CASE_RET = "{}\n";

// mutex
std::mutex g_mtx;

inline void ClosePipes(std::initializer_list<PipeTy> allPipes)
{
    for (auto p : allPipes) {
        close(p[0]);
        close(p[1]);
    }
}

inline std::vector<std::string> MakeLoginVec(std::string_view exePath)
{
    std::ostringstream cmd;
    cmd << exePath << " login -";
    return StrUtils::Split(cmd.str(), " "); // non-sensitive str ops
}

// NOTE please make sure the lifetime of the returned vector<char *> and input vector<string> is same, use this function
// with CAUTION, DO NOT destroy std::vector<std::string> before vector<char *>.
inline std::vector<char *> ExtractStrPtr(std::vector<std::string> &in)
{
    std::vector<char *> cstrings;
    cstrings.reserve(in.size() + 1);
    for (auto &s : in) {
        cstrings.push_back(s.data());
    }
    cstrings.push_back(nullptr); // important!

    return cstrings;
}

int StrDecodeToDomainIdKeyId(const std::string &str, uint32_t &domain, uint32_t &key)
{
    auto domainStrStart = NUM_3;
    auto domainStrEnd = str.find('_', domainStrStart);
    if (domainStrEnd == std::string::npos) {
        return 1; // map为空
    }
    if (!StrUtils::StrToU32(str.substr(domainStrStart, domainStrEnd - domainStrStart), domain)) {
        CCSEC_LOG_ERROR("|StrDecodeToDomainIdKeyId|END|returnF||Failed to parse string to uint32_t: " <<
                        str.substr(domainStrStart, domainStrEnd - domainStrStart));
        return -1; // 失败
    }
    auto keyStrStart = domainStrEnd + NUM_4;
    auto keyStrEnd = str.size();
    if (!StrUtils::StrToU32(str.substr(keyStrStart, keyStrEnd - keyStrStart), key)) {
        CCSEC_LOG_ERROR("|StrDecodeToDomainIdKeyId|END|returnF||Failed to parse string to uint32_t: " <<
                        str.substr(keyStrStart, keyStrEnd - keyStrStart));
        return -1;
    }
    return 0; // 成功
}

bool ReadFromPipe(int pipefd, std::vector<char> &vec)
{
    std::array<char, NUM_1024> buffer;
    ssize_t bytesRead;
    while ((bytesRead = read(pipefd, buffer.data(), buffer.size())) > 0) {
        vec.insert(vec.end(), buffer.data(), buffer.data() + bytesRead);
    }
    if (bytesRead == -1) {
        std::cerr << "Failed to read from pipe: " << strerror(errno) << std::endl;
        close(pipefd);
        return false;
    }
    return true;
}

std::pair<bool, std::string> ReadFromPipe(int pipefd)
{
    std::vector<char> out;
    auto ret = ReadFromPipe(pipefd, out);
    return {ret, {out.begin(), out.end()}};
}

bool WaitForChildProcess(pid_t pid, int *status)
{
    if (waitpid(pid, status, 0) == -1) {
        CCSEC_LOG_ERROR("Failed to wait for child process, error string: " << strerror(errno));
        return false;
    }

    if (WIFEXITED(*status)) {
        return WEXITSTATUS(*status) == 0;
    }
    if (WIFSIGNALED(*status)) {
        CCSEC_LOG_ERROR("error: cmd proc process was interrupted by signal " << WTERMSIG(*status));
    } else {
        CCSEC_LOG_ERROR("error: cmd proc process exit abnormal, status=" << *status << ", WIFEXITED(status)=" <<
                        WIFEXITED(*status));
    }

    return false;
}

bool CreatePipes(PipeTy &p1, PipeTy &p2, PipeTy &p3)
{
    if (pipe(p1.data()) == -1) {
        CCSEC_LOG_ERROR("Failed to create pipe: " << strerror(errno));
        ClosePipes({p1, p2, p3});
        return false;
    }

    if (pipe(p2.data()) == -1) {
        CCSEC_LOG_ERROR("Failed to create pipe: " << strerror(errno));
        ClosePipes({p1, p2, p3});
        return false;
    }

    if (pipe(p3.data()) == -1) {
        CCSEC_LOG_ERROR("Failed to create pipe: " << strerror(errno));
        ClosePipes({p1, p2, p3});
        return false;
    }
    return true;
}

pid_t ForkAndRunLogin(std::string_view exePath, const PipeTy &pipefdIn, const PipeTy &pipefdOut,
                      std::vector<char *> args)
{
    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "Failed to create fork: " << strerror(errno) << std::endl;
        ClosePipes({pipefdIn, pipefdOut});
        return -1;
    } else if (pid == 0) {
        close(pipefdOut[0]); // close read for child process stdout
        close(pipefdIn[1]);  // close write for child process stdin
        if (dup2(pipefdOut[1], STDOUT_FILENO) == -1) {
            std::cerr << "Failed to dup2 stdout to pipe: " << pipefdOut[1] << ", errno: " << strerror(errno)
                      << std::endl;
            _exit(1);
        }
        if (dup2(pipefdOut[1], STDERR_FILENO) == -1) {
            std::cerr << "Failed to dup2 pipe stderr: " << strerror(errno) << std::endl;
            _exit(1);
        }
        if (dup2(pipefdIn[0], STDIN_FILENO) == -1) {
            std::cerr << "Failed to dup2 pipe stdin: " << strerror(errno) << std::endl;
            _exit(1);
        }

        // Get char* arguments
        if (execv(exePath.data(), args.data()) == -1) {
            std::cerr << "Failed to execvp command: " << strerror(errno) << std::endl;
            _exit(1);
        }
    }
    return pid;
}

pid_t ForkAndRunCommand(std::string_view exePath, const PipeTy &pipefdOut, std::string_view cmdArgs)
{
    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "Failed to create fork: " << strerror(errno) << std::endl;
        return -1;
    } else if (pid == 0) {
        close(pipefdOut[0]); // close read for child process stdout

        if (dup2(pipefdOut[1], STDOUT_FILENO) == -1) {
            std::cerr << "Failed to dup2 pipe stdout: " << strerror(errno) << std::endl;
            _exit(1);
        }
        if (dup2(pipefdOut[1], STDERR_FILENO) == -1) {
            std::cerr << "Failed to dup2 pipe stderr: " << strerror(errno) << std::endl;
            _exit(1);
        }

        auto cmdArgVecStr = StrUtils::Split(cmdArgs, " "); // non-sensitive str ops
        if (execv(exePath.data(), ExtractStrPtr(cmdArgVecStr).data()) == -1) {
            std::cerr << "Failed to execvp command: " << strerror(errno) << std::endl;
            _exit(1);
        }
    }
    return pid;
}

std::pair<int, std::string> ExecOpenbaoCmd(std::string_view exePath, std::string_view acceesToken,
                                           std::string_view cmdArgs)
{
    std::lock_guard<std::mutex> lock(g_mtx);
    PipeTy loginPipefdOut = {};
    PipeTy loginPipefdIn = {};
    PipeTy cmdPipefd = {};
    int loginStatus = 0;
    int cmdStatus = 0;

    // Step 1: Creating all the pipes
    if (!CreatePipes(loginPipefdIn, loginPipefdOut, cmdPipefd)) {
        return {1, ""};
    }

    // Step 2-0: Executing the login, start child process
    auto loginVec = MakeLoginVec(exePath);
    pid_t loginPid = ForkAndRunLogin(exePath, loginPipefdIn, loginPipefdOut, ExtractStrPtr(loginVec));
    if (loginPid == -1) {
        ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
        return {1, ""};
    }

    // Step 2-1 [Parent]: write the accesstoken to child pipe
    if (write(loginPipefdIn[1], acceesToken.data(), acceesToken.size()) != static_cast<int64_t>(acceesToken.size())) {
        ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
        return {1, ""};
    }
    ClosePipes({loginPipefdIn}); // close in pipe for parent

    // Step 2-2 [Parent]: read the output of child process from pipe
    close(loginPipefdOut[1]); // explicitly close the parent write
    auto cmdRet1 = ReadFromPipe(loginPipefdOut[0]);
    if (!cmdRet1.first) {
        ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
        return {1, ""};
    }

    // Step 2-3 [Parent]: wait for child process to finish and close all pipes.
    if (!WaitForChildProcess(loginPid, &loginStatus)) {
        ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
        return cmdRet1; // in case of execv error, return the child's output
    }

    // Step 3-0: Executing the openbao/vault command, start child process
    pid_t cmdPid = ForkAndRunCommand(exePath, cmdPipefd, cmdArgs);
    if (cmdPid == -1) {
        ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
        return {1, ""};
    }

    // Step 3-1 [Parent]: read the output of child process from pipe
    close(cmdPipefd[1]); // explicitly close the parent write
    auto cmdRet2 = ReadFromPipe(cmdPipefd[0]);
    if (!cmdRet2.first) {
        ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
        return {1, ""};
    }

    // Step 3-2 [Parent]: wait for child process to finish and close all pipes.
    // HACK bao and vault cli has different return values in terms of "xxx list xxx"
    // For bao, if no key found, shell return 0 => success
    // For vault, if no key found, shell return 2 with "{}\n" => failed
    // But our key manager want to treat all cases as success, so the followings are a simple hack
    if (!WaitForChildProcess(cmdPid, &cmdStatus) &&
        memcmp(cmdRet2.second.data(), VAULT_LIST_EMPTY_CASE_RET.data(), cmdRet2.second.size()) != 0) {
        ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
        return cmdRet2; // in case of execv error, return the child's output
    }

    ClosePipes({loginPipefdIn, loginPipefdOut, cmdPipefd});
    return {0, cmdRet2.second};
}

} // namespace

bool ParseJsonAndCheck(const std::string &readResultStr, rapidjson::Document &doc)
{
    if (doc.Parse(readResultStr.c_str(), readResultStr.size()).HasParseError()) {
        CCSEC_LOG_ERROR("|ParseJsonAndCheck|END|returnF||Failed to parse json.");
        return false;
    }

    if (!doc.IsObject() || doc.ObjectEmpty()) {
        CCSEC_LOG_ERROR("|ParseJsonAndCheck|END|returnF||Check parse result type failed.");
        return false;
    }

    // get "data" and "key" object
    if (!doc.HasMember("data") || !doc["data"].HasMember("keys")) {
        CCSEC_LOG_ERROR("|ParseJsonAndCheck|END|returnF||Failed to get data.");
        return false;
    }

    if (doc["data"]["keys"].MemberCount() <= 0) {
        CCSEC_LOG_ERROR("|ParseJsonAndCheck|END|returnF|| data -> keys field is null in json.");
        return false;
    }
    return true;
}

std::string GetJsonFieldAsStr(const std::string &jsonStr)
{
    rapidjson::Document doc;
    if (!ParseJsonAndCheck(jsonStr, doc)) {
        return {};
    }

    auto lastElem = doc["data"]["keys"].MemberEnd() - 1;
    if (!lastElem->value.IsString()) { // forward check, avoid exception
        CCSEC_LOG_ERROR("|GetOpenbaoLastKeyAsStr|END|returnF|| data -> keys field is not string typed.");
        return {};
    }

    return lastElem->value.GetString(); // will not throw exception
}

int GetJsonFieldMaxInt(const std::string &jsonStr)
{
    rapidjson::Document doc;
    if (!ParseJsonAndCheck(jsonStr, doc)) {
        return -1; // error
    }

    const auto &keys = doc["data"]["keys"];

    int ret = -1;
    for (auto it = keys.MemberBegin(); it != keys.MemberEnd(); ++it) {
        if (!keys[it->name.GetString()].IsInt()) { // forward check, avoid exception
            CCSEC_LOG_ERROR("|ParseJsonAndCheck|END|returnF|| data -> keys field is not int typed.");
            return -1;
        }
        auto tmpInt = keys[it->name.GetString()].GetInt(); // will not throw exception
        ret = tmpInt > ret ? tmpInt : ret;
    }
    return ret;
}

KeyManagerRC GetJsonFieldIntPairVec(const std::string &jsonStr, std::vector<std::pair<uint32_t, uint32_t>> &out)
{
    rapidjson::Document doc;
    if (doc.Parse(jsonStr.c_str(), jsonStr.size()).HasParseError()) {
        CCSEC_LOG_ERROR("|GetJsonFieldIntPairVec|END|returnF||Failed to parse json: " << jsonStr);
        return KeyManagerRC::ERROR;
    }

    if (!doc.IsArray() || doc.Empty()) {
        CCSEC_LOG_ERROR("|GetJsonFieldIntPairVec|END|returnF||json string empty or has wrong type.");
        return KeyManagerRC::ERROR;
    }

    for (auto *it = doc.Begin(); it != doc.End(); ++it) {
        if (!it->IsString()) { // forward check, avoid exception
            CCSEC_LOG_ERROR("|GetJsonFieldIntPairVec|END|returnF|| data -> keys field is not int typed.");
            return KeyManagerRC::ERROR;
        }
        std::string tmpStr = it->GetString(); // will not throw exception
        uint32_t domain = 0;
        uint32_t key = 0;
        auto ret = StrDecodeToDomainIdKeyId(tmpStr, domain, key);
        if (ret == -1) {
            CCSEC_LOG_ERROR("|GetJsonFieldIntPairVec|END|returnF||StrDecodeToDomainIdKeyId failed.");
            return KeyManagerRC::ERROR;
        } else if (ret == 0) {
            out.emplace_back(domain, key);
        }
    }
    return KeyManagerRC::OK;
}

std::pair<KeyManagerRC, std::string> RunCommandAndGetResult(std::string_view exePath, std::string_view accessToken,
                                                            std::string_view cmdArgs)
{
    if (cmdArgs.empty()) {
        CCSEC_LOG_ERROR("|RunCommandAndGetResult|END|returnF||Error: Command string is empty.");
        return {KeyManagerRC::ERROR, {}};
    }

    if (accessToken.empty()) {
        CCSEC_LOG_ERROR("|RunCommandAndGetResult|END|returnF||Empty access token.");
        return {KeyManagerRC::ERROR, {}};
    }

    auto ret = ExecOpenbaoCmd(exePath, accessToken, cmdArgs.data());
    if (ret.first != 0) {
        CCSEC_LOG_ERROR("|RunCommandAndGetResult|END|returnF||Failed when ExecOpenbaoCmd. " << ret.second);
        return {KeyManagerRC::ERROR, {}};
    }

    if (ret.second.find("Error") != std::string::npos) {
        CCSEC_LOG_ERROR("|RunCommandAndGetResult|END|returnF||command return error, msg: " << ret.second);
        return {KeyManagerRC::ERROR, ret.second};
    }

    return {KeyManagerRC::OK, {ret.second}};
}

KeyManagerRC RunCommandAndCheck(std::string_view exePath, std::string_view accessToken, std::string_view cmdArgs)
{
    auto [rc, resultStr] = RunCommandAndGetResult(exePath, accessToken, cmdArgs);
    if (rc != KeyManagerRC::OK) {
        CCSEC_LOG_ERROR("|RunCommandAndCheck|END|returnF||Failed to execute command");
        return KeyManagerRC::ERROR;
    }

    return KeyManagerRC::OK;
}
} // namespace cdf
