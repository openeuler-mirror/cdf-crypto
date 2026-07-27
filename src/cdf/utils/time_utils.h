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

#include <cstdint>
#include <ctime>

#define UTC_TIME_FMT "%04u-%02u-%02uT%02u:%02u:%02uZ"

namespace cdf {

// utc时间字符串长度
constexpr int UTCTIME_LEN = 24;

// UTC时间结构体
struct UTCTime {
    int year;
    int month;
    int day;
    int hour;
    int min;
    int sec;
    int lastDay;     // last day of this month
    int lastLastDay; // last day of last month
};

/*
 *    @brief     UTC时间字符串格式转换成localtime.
 *    @param     timeStr    UTC时间字符串
 *    @param     len        字符串长度
 *    @return    uint32_t   返回值 0 为正确，其他为错误码
 */
uint32_t UtcTimeToLocal(char *timeStr, int len);

} // namespace cdf
