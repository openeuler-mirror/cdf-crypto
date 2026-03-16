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

#include "cdf/modules/key_management/key_manager_factory.h"

#include "cdf/modules/key_management/openbao/openbao_key_manager.h"
#include "cdf/modules/key_management/vault/vault_key_manager.h"

namespace cdf {

KeyManager *KeyManagerFactory::Borrow(KeyManagerTy type)
{
    switch (type) {
        case KeyManagerTy::OPENBAO:
            return static_cast<KeyManager *>(OpenbaoKeyManager::BorrowInstance());
        case KeyManagerTy::VAULT:
            return static_cast<KeyManager *>(VaultKeyManager::BorrowInstance());
        default:
            return nullptr;
    }
}
} // namespace cdf

#ifdef __cplusplus
extern "C" {
#endif
cdf::KeyManager *BorrowKeyManager(cdf::KeyManagerTy type)
{
    return cdf::KeyManagerFactory::Borrow(type);
}
#ifdef __cplusplus
}
#endif
