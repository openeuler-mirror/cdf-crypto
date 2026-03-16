#!/bin/bash
#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Confidential Data defensive Framework is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#

set -e

# gtest
if [ ! -d gtest ] ; then
    git clone\
        https://szv-open.codehub.huawei.com/OpenSourceCenter/google/googletest.git\
        gtest\
        -b\
        v1.14.0\
        --depth=1
fi

# krb5
if [ ! -d krb5 ] ; then
    git clone\
        https://szv-open.codehub.huawei.com/OpenSourceCenter/krb5/krb5.git\
        krb5\
        -b\
        1.21.3-htrunk2\
        --depth=1
fi

# openssl
if [ ! -d openssl ] ; then
    git clone\
        https://szv-open.codehub.huawei.com/OpenSourceCenter/openssl/openssl.git\
        openssl\
        -b\
        3.0.9-h16\
        --depth=1
fi

# pse
if [ ! -d pse ] ; then
    git clone\
        https://codehub-dg-y.huawei.com/VPP/PSE.git\
        pse\
        -b\
        tag_VPP_V300R025C10B013_002\
        --depth=1
fi

# rapidjson
if [ ! -d rapidjson ] ; then
    git clone\
        https://szv-open.codehub.huawei.com/OpenSourceCenter/Tencent/rapidjson.git\
        rapidjson\
        -b\
        6089180ecb704cb2b136777798fa1be303618975\
        --depth=1
fi

# spdlog
if [ ! -d spdlog ] ; then
    git clone\
        https://szv-open.codehub.huawei.com/OpenSourceCenter/gabime/spdlog.git\
        spdlog\
        -b\
        v1.12.0\
        --depth=1
fi

# secodefuzz
if [ ! -d secodefuzz ] ; then
    git clone\
        https://codehub-dg-y.huawei.com/software-engineering-research-community/fuzz/secodefuzz.git\
        secodefuzz\
        -b\
        v2.4.8\
        --depth=1
fi
