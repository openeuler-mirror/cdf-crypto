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

#include "cdf/modules/key_management/define.h"
#include "cdf/modules/key_management/key_manager.h"

namespace cdf {

// KMC-based Key Management
class KeyManagerFactory {
public:
    /**
     * @brief Borrow the pointer of KeyManager Singleton with certain type.
     * @param[in] type
     * @return KeyManagerRC::OK on success, other error code on failure.
     * @remark
     * - CAUTION: DO NOT free the returned pointer! The pointer comes directly
     * from singleton, free this pointer will have side effects.
     */
    static KeyManager *Borrow(KeyManagerTy type);
};

} // namespace cdf

// ------------------------
// Key Manager C Interfaces
// ------------------------

#ifdef __cplusplus
extern "C" {
/**
 * @brief Borrow the pointer of KeyManager Singleton with certain type.
 *
 * An Example of using C code with dlopen
 * see: https://tldp.org/HOWTO/C++-dlopen/thesolution.html, 3.3 Loading Classes
 * --------------------------------------
 * #include "cdf/key_management/key_manager_factory.h"
 * using xc = cdf;
 * ....
 * auto *so_handler = dlopen("/path/to/so", RTLD_LAZY);
 * auto *factory_borrow_func = dlsysm(so_handler, "BorrowKeyManager");
 * auto *openbao_km = factory_borrow_func(xc::KeyManagerTy::OPENBAO);
 * ....
 *
 * @param[in] type
 * @return KeyManagerRC::OK on success, other error code on failure.
 * @remark
 * - CAUTION: DO NOT free the returned pointer! The pointer comes directly
 * from singleton, free this pointer will have side effects.
 */
cdf::KeyManager *BorrowKeyManager(cdf::KeyManagerTy type);
}
#endif
