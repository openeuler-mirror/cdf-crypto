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

#ifndef CDF_TEST_SCOPED_ENVIRONMENT_H
#define CDF_TEST_SCOPED_ENVIRONMENT_H

#include <cstdlib>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace cdf::test {

class ScopedEnvironment {
public:
    ScopedEnvironment(std::string name, const std::string &value) : name_(std::move(name))
    {
        const char *old = std::getenv(name_.c_str());
        if (old != nullptr) {
            oldValue_ = old;
        }
        if (setenv(name_.c_str(), value.c_str(), 1) != 0) {
            throw std::runtime_error("failed to set environment variable: " + name_);
        }
        RefreshTimezone();
    }

    ~ScopedEnvironment()
    {
        if (oldValue_.has_value()) {
            (void)setenv(name_.c_str(), oldValue_->c_str(), 1);
        } else {
            (void)unsetenv(name_.c_str());
        }
        RefreshTimezone();
    }

    ScopedEnvironment(const ScopedEnvironment &) = delete;
    ScopedEnvironment &operator=(const ScopedEnvironment &) = delete;
    ScopedEnvironment(ScopedEnvironment &&) = delete;
    ScopedEnvironment &operator=(ScopedEnvironment &&) = delete;

private:
    void RefreshTimezone() const
    {
        if (name_ == "TZ") {
            tzset();
        }
    }

    std::string name_;
    std::optional<std::string> oldValue_;
};

} // namespace cdf::test

#endif // CDF_TEST_SCOPED_ENVIRONMENT_H
