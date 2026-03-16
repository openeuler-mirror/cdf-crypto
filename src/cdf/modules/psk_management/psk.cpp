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

#include "psk.h"

namespace cdf {

// 安全清理内存的辅助函数
void Psk::SecureClean()
{
    if (!pskContent.empty()) {
        // 覆盖敏感数据
        std::fill(pskContent.begin(), pskContent.end(), 0);
        // 清空并释放内存
        std::vector<uint8_t>().swap(pskContent);
    }
}

void Psk::SetPskId(uint32_t newId)
{
    this->pskId = newId;
}

uint32_t Psk::GetPskId() const
{
    return pskId;
}

void Psk::SetIssuer(const std::string &newIssuer)
{
    this->issuer = newIssuer;
}

void Psk::SetSubject(const std::string &newSubject)
{
    this->subject = newSubject;
}

std::string Psk::GetIssuer() const
{
    return issuer;
}

void Psk::SetPskLength(uint32_t newPskLength)
{
    this->pskLength = newPskLength;
}

void Psk::SetPskContent(const std::vector<uint8_t> &newContent)
{
    // 先清空现有内容
    SecureClean();
    // 拷贝新内容
    this->pskContent = newContent;
}

void Psk::SetValidDays(uint32_t newValidDays)
{
    this->validDays = newValidDays;
}

void Psk::SetBeginTime(std::time_t newBeginTime)
{
    this->beginTime = newBeginTime;
}

void Psk::SetEndTime(std::time_t newEndTime)
{
    this->endTime = newEndTime;
}

uint32_t Psk::GetPskLength() const
{
    return pskLength;
}

const std::vector<uint8_t> &Psk::GetPskContent() const
{
    return pskContent;
}

uint32_t Psk::GetValidDays() const
{
    return validDays;
}

std::time_t Psk::GetBeginTime() const
{
    return beginTime;
}

std::time_t Psk::GetEndTime() const
{
    return endTime;
}

std::string Psk::GetSubject() const
{
    return subject;
}

} // namespace cdf