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

#include <cstdint>

#include "cdf/modules/cryption/native_cryptor_def.h"

namespace cdf {

/**
 * @brief 获取随机数接口初始化 全局初始化一次即可
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
CcsecCryptErrorCode RandInit();

/**
 * @brief 获取随机数
 * @param randBuff [OUT] 随机数
 * @param randDataLength [IN] 随机数长度 限制长度为(0,65536]
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
CcsecCryptErrorCode GetRand(uint8_t *randBuff, const uint32_t randDataLength);

/**
 * @brief 获取随机数接口去初始化 全局去初始化一次即可
 * @return void
 */
void RandDeinit();

/**
 * GetSecurePwd 获取安全密码口令
 * @param pwdBuff [OUT] 安全密码口令
 * @param pwdLength [IN] 安全密码口令长度，范围: [8, 32]
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
CcsecCryptErrorCode GetSecurePwd(uint8_t *pwdBuff, const uint32_t pwdLength);

} // namespace cdf