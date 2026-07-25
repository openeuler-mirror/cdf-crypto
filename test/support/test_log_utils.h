/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Confidential Data defensive Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 */

#pragma once

#include <iostream>

namespace cdf::test {
inline void TestLogCallback(int level, const char *msg)
{
    std::cout << "|level:|" << level << " |msg: " << msg << std::endl;
}
} // namespace cdf::test
