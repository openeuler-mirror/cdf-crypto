/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
          * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#pragma once

#include "gtest/gtest.h"

#include "cdf/modules/key_management/key_manager.h"
#include "cdf/modules/key_management/key_manager_factory.h"

namespace cdf::test {

inline void EnsureKmUninited(KeyManager *km)
{
    if (km->CheckInited()) {
        auto rc = km->UnInit();
        ASSERT_EQ(rc, KeyManagerRC::OK);
    }
}

inline void EnsureKmUninited(KeyManagerTy type)
{
    auto *km = KeyManagerFactory::Borrow(type);
    EnsureKmUninited(km);
}

inline void SetExternalLogCallBack(int level, const char *msg)
{
    std::cout << "|level:|" << level << " |msg: " << msg << std::endl;
}

} // namespace cdf::test
