/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
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

#include <any>
#include <functional>
#include <iostream>
#include <mutex>
#include <typeinfo>
#include <unordered_map>

#include "cdf/modules/psk_management/psk_define.h"

namespace cdf {
using CreatePskCallBack = PskManagerRC (*)(const uint32_t pskId, const std::vector<std::byte> pskCiphertext);

using UpdatePskCallBack = PskManagerRC (*)(const uint32_t pskId, const std::vector<std::byte> pskCiphertext);

using DeletePskCallBack = PskManagerRC (*)(const uint32_t pskId);

enum class PskCallBackType : int {
    CREATE_PSK = 0,
    UPDATE_PSK = 1,
    DELETE_PSK = 2,
};

class PskCallbackMgr {
public:
    static PskCallbackMgr &GetInstance();

    // 注册创建PSK凭证接口的回调函数
    PskManagerRC RegisterCreatePskCallBack(CreatePskCallBack cb);

    // 注册更新PSK凭证接口的回调函数
    PskManagerRC RegisterUpdatePskCallBack(UpdatePskCallBack cb);

    // 注册删除PSK凭证接口的回调函数
    PskManagerRC RegisterDeletePskCallBack(DeletePskCallBack cb);

    // 判断是否注册该回调函数
    PskManagerRC IsCallbackRegistered(PskCallBackType id);

    // 触发回调函数调用
    template <typename... Args> PskManagerRC Trigger(PskCallBackType id, Args... args)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = callbacks_.find(id);
        if (it == callbacks_.end()) {
            return PskManagerRC::CALL_BACK_UNREGISTED; // 未注册错误码
        }

        try {
            auto &func = std::any_cast<std::function<PskManagerRC(Args...)> &>(it->second);
            return func(std::forward<Args>(args)...);
        } catch (const std::bad_any_cast &e) {
            return PskManagerRC::CALL_BACK_TYPE_MISMATCH;
        } catch (const std::exception &e) {
            // 情况2：其他标准库异常（如std::function调用异常）
            return PskManagerRC::CALL_BACK_STANDARD_LIBRARY_EXCEPTION;
        } catch (...) {
            // 情况3：未知异常（如内存错误）
            return PskManagerRC::CALL_BACK_UN_KNOWN;
        }
    }

private:
    PskCallbackMgr() = default;

    // 回调函数的注册方法
    template <typename... Args> void Register(PskCallBackType id, std::function<PskManagerRC(Args...)> callback)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_[id] = std::move(callback);
        return;
    }

    std::unordered_map<PskCallBackType, std::any> callbacks_;
    std::mutex mutex_;
};
}