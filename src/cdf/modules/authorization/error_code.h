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

namespace cdf {

// Authorization Return Code Definition
enum class AuthRC : int {
    OK = 0,                          // success
    FAILED = 100,                    // auth failed
    CONF_CONFLICT = 101,             // config conflict
    CONF_INVALID = 102,              // config invalid
    PARAM_ERROR = 103,               // parm error
    CONF_FORMAT_INVALID = 104,       // config file format invalid
    NO_SUCH_USER = 105,              // user not exist
    USER_EXIST = 106,                // user has existed
    EMPTY_USERNAME = 107,            // username is empty
    NO_SUCH_ROLE = 108,              // role not exit
    EMPTY_ROLE = 109,                // roleName is empty
    ROLE_EXISTED = 110,              // role has existed
    NO_SUCH_PERMISSION = 111,        // permission not exist
    ROLE_IN_USE = 112,               // role still in use
    PERMISSION_IN_USE = 113,         // permission still in use
    PERMISSION_EXISTED = 114,        // permission has existed
    PERMISSION_BIND_FAILED = 115,    // bind role and permission failed
    MALLOC_FAILED = 116,             // malloc memory failed
    NOT_SUPPORTED_TYPE = 117,        // not supported auth type
    SET_EXTERNAL_LOGGER_FAILED = 118 // set external logger failed
};

} // namespace cdf
