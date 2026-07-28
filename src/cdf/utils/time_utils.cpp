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

#include "cdf/utils/time_utils.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "securec.h"

#include "cdf/base/common_define.h"

namespace cdf {

namespace {

// 获取本地时间时区
int GetTimeZone()
{
    time_t utcTime = 0;
    struct tm tmTime;
    int timeZone;

    localtime_r(&utcTime, &tmTime); // 转成当地时间

    timeZone = (tmTime.tm_hour > NUM_12) ? (tmTime.tm_hour -= NUM_24) : tmTime.tm_hour;

    return timeZone;
}

// 处理跨时区时间
void TranseTimeZoneT(UTCTime *utcTime)
{
    if (utcTime == nullptr) {
        printf("error: input utcTime is nullptr\n");
        return;
    }

    int timeZone = GetTimeZone();
    utcTime->hour = utcTime->hour + timeZone;

    if (utcTime->hour >= NUM_24) { // if >24, day+1
        utcTime->hour -= NUM_24;
        utcTime->day += 1;
        if (utcTime->day > utcTime->lastDay) { // next month,  day-lastday of this month
            utcTime->day -= utcTime->lastDay;
            utcTime->month += 1;

            if (utcTime->month > NUM_12) { //  next year , month-12
                utcTime->month -= NUM_12;
                utcTime->year += 1;
            }
        }
    }

    if (utcTime->hour < 0) { // if <0, day-1
        utcTime->hour += NUM_24;
        utcTime->day -= 1;
        if (utcTime->day < 1) { // month-1, day=last day of last month
            utcTime->day = utcTime->lastLastDay;
            utcTime->month -= 1;
            if (utcTime->month < 1) {
                utcTime->month = NUM_12;
                utcTime->year -= 1;
            }
        }
    }
}

// 解析当月与上月天数
void ParseDayAmount(const int *month, const int *year, int *lastday, int *lastlastday)
{
    int invalidParam =
        static_cast<int>(month == nullptr || year == nullptr || lastday == nullptr || lastlastday == nullptr);
    int bMonthFlag = static_cast<int>(*month == 1 || *month == NUM_3 || *month == NUM_5 || *month == NUM_7 ||
                                      *month == NUM_8 || *month == NUM_10 || *month == NUM_12);
    int sMonthFlag = static_cast<int>(*month == NUM_4 || *month == NUM_6 || *month == NUM_9 || *month == NUM_11);
    if (invalidParam != 0) {
        return;
    }
    bool bLeapMonth = ((*year % NUM_400 == 0) || (*year % NUM_4 == 0 && *year % NUM_100 != 0));
    if (bMonthFlag != 0) {
        *lastday = NUM_31;
        if (*month == NUM_3) {
            if (bLeapMonth) {
                *lastlastday = NUM_29;
            } else {
                *lastlastday = NUM_28;
            }
        }

        if (*month == NUM_8) {
            *lastlastday = NUM_31;
        }
    } else if (sMonthFlag != 0) {
        *lastday = NUM_30;
        *lastlastday = NUM_31;
    } else {
        *lastlastday = NUM_31;
        if (bLeapMonth) {
            *lastday = NUM_29;
        } else {
            *lastday = NUM_28;
        }
    }
}
} // namespace

// UTC时间转为本地时间
uint32_t UtcTimeToLocal(char *timeStr, [[maybe_unused]]int len)
{
    if (timeStr == nullptr) {
        return 1;
    }

    UTCTime utcTime;
    // 格式化输入UTC时间
    auto ret = sscanf_s(timeStr, "%04d-%02d-%02dT%02d:%02d:%02dZ", &utcTime.year, &utcTime.month, &utcTime.day,
                        &utcTime.hour, &utcTime.min, &utcTime.sec);
    if (ret != NUM_6) {
        return 1;
    }
    ParseDayAmount(&utcTime.month, &utcTime.year, &utcTime.lastDay, &utcTime.lastLastDay);

    TranseTimeZoneT(&utcTime);

    // 格式化输出本地时间
    auto secFuncRet = sprintf_s(timeStr, UTCTIME_LEN + 1, "%04d/%02d/%02d %02d:%02d:%02d ", utcTime.year,
                                utcTime.month, utcTime.day, utcTime.hour, utcTime.min, utcTime.sec);
    if (secFuncRet == -1) {
        printf("sprintf_s failed, secFuncRet = %d, strTime is:%s\n", secFuncRet, timeStr);
        return 1;
    }
    return 0;
}

} // namespace cdf