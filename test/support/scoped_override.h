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

#ifndef CDF_TEST_SCOPED_OVERRIDE_H
#define CDF_TEST_SCOPED_OVERRIDE_H

#include <utility>

namespace cdf::test {

template<typename T>
class ScopedOverride {
public:
    ScopedOverride(T &slot, T replacement) : slot_(slot), old_(slot)
    {
        slot_ = std::move(replacement);
    }

    ~ScopedOverride()
    {
        slot_ = std::move(old_);
    }

    ScopedOverride(const ScopedOverride &) = delete;
    ScopedOverride &operator=(const ScopedOverride &) = delete;
    ScopedOverride(ScopedOverride &&) = delete;
    ScopedOverride &operator=(ScopedOverride &&) = delete;

private:
    T &slot_;
    T old_;
};

} // namespace cdf::test

#endif // CDF_TEST_SCOPED_OVERRIDE_H
