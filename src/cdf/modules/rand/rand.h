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
#include <string>

#include "cdf/modules/cryption/native_cryptor_def.h"

namespace cdf {

constexpr uint32_t DEFAULT_SECURE_PWD_RETRY_TIMES = 10;

/**
 * @brief 随机数模块配置结构体
 * @details 用于配置随机数生成器的初始化参数，包括熵源、DRBG类型等
 * @note 当前版本限制说明：
 *       - 底层使用 OpenSSL 3.0 EVP_RAND API，创建私有 DRBG 实例
 *       - 与 OpenSSL 全局 RAND_* 状态完全隔离，初始化成功后按配置创建实例
 *       - healthCheckInterval 通过 EVP_RAND_get_state 实现健康检查
 */
struct RandConfig {
    /**
     * @brief DRBG（确定性随机位生成器）类型
     * @details 指定使用的DRBG算法类型
     * 可选值：
     *   - "CTR-DRBG"：基于分组密码的计数器模式DRBG（默认，推荐）
     *   - "HASH-DRBG"：基于哈希函数的DRBG
     *   - "HMAC-DRBG"：基于HMAC的DRBG
     * @note 通过 EVP_RAND_fetch 获取算法实现，初始化成功后选择对应 DRBG
     */
    std::string drbgType = "CTR-DRBG";

    /**
     * @brief 种子来源
     * @details 指定随机数种子的获取来源
     * 可选值：
     *   - "SEED-SRC"：使用系统默认熵源（默认）
     *   - "OS"：非 FIPS 模式下使用 SEED-SRC parent，并在 DRBG 实例化前调用 RAND_poll()
     *           触发 OpenSSL OS 熵源补充采集；FIPS 模式下 parent 仍按 fipsMode 规则选择
     *   - "HARDWARE"：使用 OpenSSL JITTER RAND 作为 parent 熵源
     *   - "CUSTOM"：从 customSeedProvider 指定的 Provider 获取 SEED-SRC 作为 parent 熵源
     * @note seedSource 会影响 EVP_RAND_fetch 的 parent RAND 名称或 provider 属性约束；
     *       fipsMode=true 且 seedSource!="CUSTOM" 时，parent 使用带 fips=yes 属性约束的 JITTER；
     *       seedSource="CUSTOM" 时 parent 使用 provider=<customSeedProvider> 属性约束
     */
    std::string seedSource = "SEED-SRC";

    /**
     * @brief FIPS模式开关
     * @details 是否使用 FIPS Provider 属性约束获取 DRBG/parent RAND
     * 默认值：false（关闭）
     * @note 启用后先加载 FIPS Provider，再用 fips=yes 属性获取 DRBG 算法；
     *       非 CUSTOM 熵源下 parent 使用带 fips=yes 属性约束的 JITTER。
     *       是否可用取决于运行环境是否安装并启用对应 Provider/RAND 实现
     */
    bool fipsMode = false;

    /**
     * @brief 自定义种子提供器名称（条件生效参数）
     * @details 仅当 seedSource 设置为 "CUSTOM" 时生效，用于指定 OSSL_PROVIDER_load()
     * 加载的 provider 名称，并通过 provider=<customSeedProvider> 属性约束获取 SEED-SRC。
     * seedSource!="CUSTOM" 时该字段不参与 parent 选择
     * @note seedSource="CUSTOM" 且 customSeedProvider 为空时，RandInit 返回错误
     */
    std::string customSeedProvider;

    /**
     * @brief 安全强度 (bits)
     * @details 传递给 EVP_RAND_instantiate 的 strength 参数
     * 根据 NIST SP 800-90A / SP 800-57 定义的安全强度等级：
     *
     *   强度等级 | 数值(bits) | 等效安全域         | 对应 DRBG 实现
     *   --------|-----------|---------------------|----------------------
     *   低 (L)  |   112     | 3DES / RSA-2048   | 非推荐，仅兼容旧系统
     *   中 (M)  |   128     | AES-128 / SHA-256 | CTR(AES-128) / HASH(SHA-256)
     *   高 (H)  |   192     | AES-192 / SHA-384 | CTR(AES-192) / HASH(SHA-384)
     *   最高   |   256     | AES-256 / SHA-512 | CTR(AES-256) / HASH(SHA-512)
     *
     *   默认值: 256 (最高安全强度)
     *   有效范围: [112, 256]
     *   @note CTR-DRBG 强度受 AES 密钥长度约束 (128/192/256)
     *         HASH-DRBG / HMAC-DRBG 强度受摘要位宽约束
     *   @note HASH-DRBG / HMAC-DRBG 支持 [112, 256] 范围内的强度值；
     *         非边界值会选择满足该强度上限的摘要算法，例如 (128,192] 使用 SHA-384
     */
    uint32_t securityStrength = 256;

    /**
     * @brief 预测抵抗 (Prediction Resistance)
     * @details 每次 EVP_RAND_generate 前是否重新从 parent 熵源取种
     * 默认 false（性能优先），敏感场景（如密钥生成）可启用
     */
    bool predictionResistance = false;

    /**
     * @brief 健康检查间隔（生效参数）
     * @details 指定随机数生成器健康检查的时间间隔（单位：毫秒）
     * 设置为0表示禁用周期性健康检查（默认）
     * 建议值：1000-60000（1秒到1分钟）
     * @note 通过 EVP_RAND_get_state 检查 DRBG 运行状态
     */
    uint32_t healthCheckInterval = 0;
};

/**
 * @brief 随机数生成器健康状态结构体
 * @details 用于报告随机数生成器的运行状态和健康状况
 */
struct RandHealthStatus {
    /**
     * @brief 健康状态标志
     * @details 指示随机数生成器是否处于健康状态
     * true：运行正常，可安全使用
     * false：检测到异常，建议停止使用并重新初始化
     */
    bool isHealthy = false;

    /**
     * @brief 熵充足性标志
     * @details 指示当前熵池是否足够
     * true：熵充足，可以安全生成随机数
     * false：熵不足，可能影响随机数质量
     */
    bool entropySufficient = false;

    /**
     * @brief 错误计数
     * @details 记录自初始化以来发生的错误次数
     * 用于评估随机数生成器的可靠性
     */
    uint32_t errorCount = 0;
};

/**
 * @brief 随机数模块初始化
 * @details 初始化随机数生成器，配置熵源和DRBG类型。
 * 全局只需调用一次，支持带默认参数的自动初始化。
 * @param config 初始化配置参数，使用默认值即可满足大多数场景
 *               - drbgType: DRBG类型，默认 "CTR-DRBG"
 *               - seedSource: 种子来源，默认 "SEED-SRC"
 *               - fipsMode: FIPS模式，默认 false
 *               - customSeedProvider: 自定义种子提供器，默认为空
 *               - securityStrength: 安全强度，默认 256，范围 [112, 256]
 *               - predictionResistance: 预测抵抗，默认 false
 *               - healthCheckInterval: 健康检查间隔(ms)，默认 0
 * @return 成功返回 CCSEC_CRYPT_OK，失败返回对应错误码
 * @note 底层通过 EVP_RAND_fetch + EVP_RAND_CTX_new 创建私有 DRBG 实例
 * @note 在首次调用 GetRand() 时会自动使用默认配置初始化
 * @note 模块已初始化时，RandInit(config) 直接返回 CCSEC_CRYPT_OK，不会切换已有配置；
 *       如需更换配置，请先调用 RandDeinit()
 * @code
 * // 使用默认配置初始化
 * auto ret = RandInit();
 *
 * // 使用自定义配置初始化
 * RandConfig config;
 * config.drbgType = "HMAC-DRBG";
 * config.fipsMode = true;
 * auto ret = RandInit(config);
 * @endcode
 */
CcsecCryptErrorCode RandInit(const RandConfig &config = RandConfig{});

/**
 * @brief 获取随机数
 * @details 生成指定长度的随机数。支持自动初始化特性：若模块未初始化，
 *          首次调用时会自动使用默认配置（RandConfig{}）进行初始化。
 * @note 若 predictionResistance 启用，每次调用前从 parent 熵源重取种
 * @param randBuff [OUT] 随机数输出缓冲区
 * @param randDataLength [IN] 随机数长度，限制范围为 (0, 65536]
 * @return 成功返回 CCSEC_CRYPT_OK，失败返回对应错误码
 * @note 自动初始化仅使用默认配置，如需自定义配置请先调用 RandInit()
 */
CcsecCryptErrorCode GetRand(uint8_t *randBuff, const uint32_t randDataLength);

/**
 * @brief 获取随机数接口去初始化 全局去初始化一次即可
 * @return void
 */
void RandDeinit();

/**
 * @brief 获取随机数生成器健康状态
 * @details 获取当前随机数生成器的运行状态，包括健康标志、熵充足性、错误计数等信息
 * @param status [OUT] 健康状态结构体，包含以下字段：
 *               - isHealthy: 是否处于健康状态
 *               - entropySufficient: 熵是否充足
 *               - errorCount: 错误计数
 * @return 成功返回 CCSEC_CRYPT_OK，失败返回对应错误码
 * @note 在调用 RandInit() 之前调用此函数将返回未初始化状态
 */
CcsecCryptErrorCode GetRandHealthStatus(RandHealthStatus &status);

#ifdef CDF_RAND_TESTING
uint32_t GetRandHealthCheckCountForTest();
#endif

/**
 * GetSecurePwd 获取安全密码口令
 * @param pwdBuff [OUT] 安全密码口令
 * @param pwdLength [IN] 安全密码口令长度，范围: [8, 32]
 * @param retryTimes [IN] 重试次数，默认10次；传入正数时使用指定次数，0为非法参数
 * @return 失败返回错误码 成功返回 CCSEC_CRYPT_OK
 */
CcsecCryptErrorCode GetSecurePwd(uint8_t *pwdBuff, const uint32_t pwdLength,
                                 const uint32_t retryTimes = DEFAULT_SECURE_PWD_RETRY_TIMES);

} // namespace cdf
