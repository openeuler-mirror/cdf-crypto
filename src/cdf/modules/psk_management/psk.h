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

#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace cdf {

class Psk {
public:
    void SetPskId(uint32_t newId);
    void SetIssuer(const std::string &newIssuer);
    void SetSubject(const std::string &newSubject);
    void SetPskLength(uint32_t newPskLength);
    void SetPskContent(const std::vector<uint8_t> &newContent);
    void SetValidDays(uint32_t newValidDays);
    void SetBeginTime(std::time_t newBeginTime);
    void SetEndTime(std::time_t newEndTime);

    uint32_t GetPskId() const;
    std::string GetIssuer() const;
    std::string GetSubject() const;
    uint32_t GetPskLength() const;
    const std::vector<uint8_t>& GetPskContent() const;
    uint32_t GetValidDays() const;
    std::time_t GetBeginTime() const;
    std::time_t GetEndTime() const;

private:
    uint32_t pskId;                  // psk凭证ID
    std::string issuer;              // 签发人
    std::string subject;             // 使用人
    uint32_t pskLength;              // psk凭证长度
    std::vector<uint8_t> pskContent; // psk凭证key
    uint32_t validDays;              // 有效期天数
    std::time_t beginTime;           // 有效期开始时间
    std::time_t endTime;             // 有效期结束时间

    void SecureClean();
};

} // namespace cdf
