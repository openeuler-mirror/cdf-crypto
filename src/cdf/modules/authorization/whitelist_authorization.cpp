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

#include "cdf/modules/authorization/whitelist_authorization.h"

#include <algorithm>
#include <fstream>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"

#include "cdf/base/ccsec_logger.h"

namespace rj = rapidjson;

namespace cdf {

AuthRC WhitelistAuthorization::Initialize(std::string_view conf)
{
    if (conf.size() > MAX_ALLOWED_CONF_LENGTH) {
        CCSEC_LOG_ERROR("|Initialize|END|returnF||conf is too large");
        return AuthRC::PARAM_ERROR;
    }
    if (conf.empty()) {
        CCSEC_LOG_ERROR("|Initialize|END|returnF||conf is empty");
        return AuthRC::CONF_FORMAT_INVALID;
    }
    rj::Document document;
    auto conf_str = std::string(conf);
    if (document.Parse<rj::kParseIterativeFlag>(conf_str.c_str()).HasParseError()) {
        CCSEC_LOG_ERROR("|Initialize|END|returnF||document parse has error");
        return AuthRC::CONF_FORMAT_INVALID;
    }

    if (!document.IsArray()) {
        CCSEC_LOG_ERROR("|Initialize|END|returnF||document format error");
        return AuthRC::CONF_FORMAT_INVALID;
    }

    for (rj::SizeType i = 0; i < document.Size(); ++i) {
        if (!document[i].IsObject()) {
            CCSEC_LOG_ERROR("|Initialize|END|returnF||Document format error");
            return AuthRC::CONF_FORMAT_INVALID;
        }

        if (!document[i].HasMember("user") || !document[i]["user"].IsString()) {
            CCSEC_LOG_ERROR("|Initialize|END|returnF||Node member user is wrong or is not a string type");
            return AuthRC::CONF_FORMAT_INVALID;
        }
        if (!document[i].HasMember("allow") || !document[i]["allow"].IsBool()) {
            CCSEC_LOG_ERROR("|Initialize|END|returnF||Node member allow is wrong or is not a bool type");
            return AuthRC::CONF_FORMAT_INVALID;
        }

        std::string userName = document[i]["user"].GetString();
        bool access = document[i]["allow"].GetBool();

        auto iter = whitelist_.find(userName);
        if (iter == whitelist_.end()) {
            whitelist_.insert({userName, access});
        } else {
            if (whitelist_[userName] != access) {
                CCSEC_LOG_ERROR("|Initialize|END|returnF||User has two different access");
                return AuthRC::CONF_CONFLICT;
            }
        }
    }
    CCSEC_LOG_INFO("|Initialize|END|returnS||ServerInit Succeed, size: " << whitelist_.size());
    return (AuthRC::OK);
}

AuthRC WhitelistAuthorization::CheckPermission(std::string_view principal, [[maybe_unused]] std::string_view resource,
                                               [[maybe_unused]] std::string_view operation)
{
    if (principal.empty() || principal.size() > MAX_ALLOWED_NAME_LENGTH) {
        CCSEC_LOG_ERROR("|CheckPermission|END|returnF||principal is empty or too large");
        return AuthRC::PARAM_ERROR;
    }
    const std::string p_str = std::string(principal);
    if (whitelist_.count(p_str) > 0) {
        return whitelist_[p_str] ? AuthRC::OK : AuthRC::FAILED;
    }
    return AuthRC::FAILED;
}

AuthRC WhitelistAuthorization::UnInitialize()
{
    whitelist_.clear();
    return (AuthRC::OK);
}

AuthRC WhitelistAuthorization::GetAllPrincipals(std::vector<std::string> &principals)
{
    principals.clear();
    std::for_each(whitelist_.begin(), whitelist_.end(), [&principals](const std::pair<std::string, bool> &principal) {
        principals.emplace_back(principal.first);
    });
    return (AuthRC::OK);
}
} // namespace cdf
