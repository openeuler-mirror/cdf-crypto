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

#include "cdf/modules/psk_management/psk_callback_mgr.h"

#include "cdf/base/ccsec_logger.h"

namespace cdf {
PskCallbackMgr &PskCallbackMgr::GetInstance()
{
    static PskCallbackMgr instance;
    return instance;
}

PskManagerRC PskCallbackMgr::RegisterCreatePskCallBack(CreatePskCallBack cb)
{
    if (cb == nullptr) {
        CCSEC_LOG_ERROR("|RegisterCreatePskCallBack|END|returnF|param is nullptr");
        return PskManagerRC::INVALID_PARAM;
    }
    std::function<PskManagerRC(const uint32_t pskId, const std::vector<std::byte> pskCiphertext)> createPskCb = cb;
    PskCallbackMgr &instance = PskCallbackMgr::GetInstance();
    instance.Register(PskCallBackType::CREATE_PSK, createPskCb);
    CCSEC_LOG_DEBUG("|RegisterCreatePskCallBack|END|returnS|register success");
    return PskManagerRC::OK;
}

PskManagerRC PskCallbackMgr::RegisterUpdatePskCallBack(UpdatePskCallBack cb)
{
    if (cb == nullptr) {
        CCSEC_LOG_ERROR("|RegisterUpdatePskCallBack|END|returnF|param is nullptr");
        return PskManagerRC::INVALID_PARAM;
    }
    std::function<PskManagerRC(const uint32_t pskId, const std::vector<std::byte> pskCiphertext)> updatePskCb = cb;
    PskCallbackMgr &instance = PskCallbackMgr::GetInstance();
    instance.Register(PskCallBackType::UPDATE_PSK, updatePskCb);
    CCSEC_LOG_DEBUG("|RegisterUpdatePskCallBack|END|returnS|register success");
    return PskManagerRC::OK;
}

PskManagerRC PskCallbackMgr::RegisterDeletePskCallBack(DeletePskCallBack cb)
{
    if (cb == nullptr) {
        CCSEC_LOG_ERROR("|RegisterDeletePskCallBack|END|returnF|param is nullptr");
        return PskManagerRC::INVALID_PARAM;
    }
    std::function<PskManagerRC(const uint32_t pskId)> deletePskCb = cb;
    PskCallbackMgr &instance = PskCallbackMgr::GetInstance();
    instance.Register(PskCallBackType::DELETE_PSK, deletePskCb);
    CCSEC_LOG_DEBUG("|RegisterDeletePskCallBack|END|returnS|register success");
    return PskManagerRC::OK;
}

PskManagerRC PskCallbackMgr::IsCallbackRegistered(PskCallBackType id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = callbacks_.find(id);
    if (it == callbacks_.end()) {
        return PskManagerRC::CALL_BACK_UNREGISTED;
    }
    return PskManagerRC::OK;
}

}