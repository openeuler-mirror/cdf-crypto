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

enum class CryptionToolRc {
    OK = 0,                    // success
    PARAM_INVALID = 1,         // input param is invalid
    INTERNAL_ERROR = 2,        // handle cmd failed
    ENCRYPT_ERROR = 3,         // encrypt failed
    ACTIVE_KEY_ERROR = 4,      // active key fail
    UPDATE_ROOT_KEY_ERROR = 5, // update root key failed
    ENCRYPT_INTERNAL_ERROR = 6 // internal error
};

} // namespace cdf
