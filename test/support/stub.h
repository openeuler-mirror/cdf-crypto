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

#ifndef __STUB_H__
#define __STUB_H__

// linux
#include <sys/mman.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
// c
#include <cstddef>
#include <cstring>
// c++
#include <iostream>
#include <map>
// project
#include "securec.h"

namespace cdf::test {

constexpr int NUM_2 = 2;
constexpr int NUM_4 = 4;
constexpr int NUM_31 = 31;
constexpr int PAGE_SIZE = 4096;
constexpr int MAX_STUB_FILE_SIZE = 1 * 1024 * 1024;
constexpr int ORM_STATUS_ERROR = -1;
#define ADDR(CLASS_NAME, MEMBER_NAME) (&(CLASS_NAME)::(MEMBER_NAME))

/**********************************************************
                  replace function
**********************************************************/
#define CACHEFLUSH(addr, size) __builtin___clear_cache((addr), (addr) + (size))

#if defined(__aarch64__) || defined(_M_ARM64)
constexpr uint16_t CODESIZE = 16U;
constexpr uint16_t CODESIZE_MIN = 16U;
constexpr uint16_t CODESIZE_MAX = CODESIZE;
#define REPLACE_FAR(t, fn, fnStub)                                       \
    do {                                                                 \
        ((reinterpret_cast<uint32_t *>(fn)))[0] = 0x58000040 | 9;        \
        ((reinterpret_cast<uint32_t *>(fn)))[1] = 0xd61f0120 | (9 << 5); \
        *(long long *)((fn) + 8) = (long long)(fnStub);                  \
        CACHEFLUSH(reinterpret_cast<char *>(fn), CODESIZE);              \
    } while (0)
#define REPLACE_NEAR(t, fn, fnStub) REPLACE_FAR((t), (fn), (fnStub))
#elif defined(__arm__) || defined(_M_ARM)
constexpr uint16_t CODESIZE = 8U;
constexpr uint16_t CODESIZE_MIN = 8U;
constexpr uint16_t CODESIZE_MAX = CODESIZE;
#define REPLACE_FAR(t, fn, fnStub)                  \
    do {                                            \
        ((uint32_t *)(fn))[0] = 0xe51ff004;         \
        ((uint32_t *)(fn))[1] = (uint32_t)(fnStub); \
        CACHEFLUSH((char *)(fn), CODESIZE);         \
    } while (0)
#define REPLACE_NEAR(t, fn, fnStub) REPLACE_FAR((t), (fn), (fnStub))
#elif defined(__thumb__) || defined(_M_THUMB)
#error "Thumb is not supported"
#else // __i386__ _x86_64__
constexpr uint16_t CODESIZE = 13U;
constexpr uint16_t CODESIZE_MIN = 5U;
constexpr uint16_t CODESIZE_MAX = CODESIZE;
#define REPLACE_FAR(t, fn, fnStub)                      \
    do {                                                \
        *(fn) = 0x49;                                   \
        *((fn) + 1) = 0xbb;                             \
        *(long long *)((fn) + 2) = (long long)(fnStub); \
        *((fn) + 10) = 0x41;                            \
        *((fn) + 11) = 0xff;                            \
        *((fn) + 12) = 0xe3;                            \
    } while (0)

// 5 byte(jmp rel32)
// Make cleancode happy
// clang-format off
#define REPLACE_NEAR(t, fn, fnStub)                                 \
    do {                                                            \
        *(fn) = 0xE9;                                               \
        *(int *)((fn) + 1) = (int)((fnStub) - (fn) - CODESIZE_MIN); \
    } while (0)
#endif
// clang-format on

struct FuncStub {
    char *fn;
    unsigned char codeBuf[CODESIZE];
    bool farJmp;
};

class Stub {
public:
    Stub()
    {
        m_pagesize = sysconf(_SC_PAGE_SIZE);
        if (m_pagesize < 0) {
            m_pagesize = PAGE_SIZE;
        }
    }

    ~Stub()
    {
        int ret;
        std::map<char *, FuncStub *>::iterator iter;
        struct FuncStub *pstub = nullptr;
        for (iter = m_result.begin(); iter != m_result.end(); iter++) {
            pstub = iter->second;
            if (mprotect(Pageof(pstub->fn), m_pagesize * NUM_2, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                if (pstub->farJmp) {
                    ret = memcpy_s(pstub->fn, CODESIZE_MAX, pstub->codeBuf, CODESIZE_MAX);
                } else {
                    ret = memcpy_s(pstub->fn, CODESIZE_MIN, pstub->codeBuf, CODESIZE_MIN);
                }
                if (ret != EOK) {
                    std::cout << "|system mem||||System mem error." << std::endl;
                }
                mprotect(Pageof(pstub->fn), m_pagesize * NUM_2, PROT_READ | PROT_EXEC);
            }
            iter->second = nullptr;
            delete pstub;
        }

        return;
    }

    template <typename T, typename S> void Set(T addr, S addr_stub)
    {
        char *fn;
        char *fnStub;
        fn = Addrof(addr);
        fnStub = Addrof(addr_stub);
        struct FuncStub *pstub = new FuncStub;
        // start
        pstub->fn = fn;

        if (Distanceof(fn, fnStub)) {
            pstub->farJmp = true;
            if (memcpy_s(pstub->codeBuf, CODESIZE, fn, CODESIZE_MAX) != EOK) {
                delete pstub;
                return;
            }
        } else {
            pstub->farJmp = false;
            if (memcpy_s(pstub->codeBuf, CODESIZE, fn, CODESIZE_MIN) != EOK) {
                delete pstub;
                return;
            }
        }

        if (mprotect(Pageof(pstub->fn), m_pagesize * NUM_2, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            delete pstub;
            return; // older is throw "stub set memory protect to w+r+x faild"
        }

        if (pstub->farJmp) {
            REPLACE_FAR(this, fn, (intptr_t)fnStub);
        } else {
            REPLACE_NEAR(this, fn, fnStub);
        }

        if (mprotect(Pageof(pstub->fn), m_pagesize * NUM_2, PROT_READ | PROT_EXEC) == -1) {
            delete pstub;
            return; // older is throw "stub set memory protect to r+x failed"
        }
        m_result.insert(std::pair<char *, FuncStub *>(fn, pstub));
        return;
    }

    template <typename T> void Reset(T addr)
    {
        char *fn = Addrof(addr);
        std::map<char *, FuncStub *>::iterator iter = m_result.find(fn);
        if (iter == m_result.end()) {
            return;
        }
        struct FuncStub *pstub = iter->second;

        if (mprotect(Pageof(pstub->fn), m_pagesize * NUM_2, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            return; // older is throw "stub reset memory protect to w+r+x faild"
        }

        if (pstub->farJmp) {
            if (memcpy_s(pstub->fn, CODESIZE_MAX, pstub->codeBuf, CODESIZE_MAX) != EOK) {
                return;
            }
        } else {
            if (memcpy_s(pstub->fn, CODESIZE_MIN, pstub->codeBuf, CODESIZE_MIN) != EOK) {
                return;
            }
        }

        if (mprotect(Pageof(pstub->fn), m_pagesize * NUM_2, PROT_READ | PROT_EXEC) == -1) {
            return; // older is throw "stub reset memory protect to r+x failed"
        }
        m_result.erase(iter);
        delete pstub;

        return;
    }

private:
    char *Pageof(char *addr)
    {
        return reinterpret_cast<char *>(reinterpret_cast<unsigned long>(reinterpret_cast<uintptr_t>(addr)) &
                                        ~(m_pagesize - 1));
    }

    template <typename T> char *Addrof(T addr)
    {
        union {
            T s;
            char *d;
        } ut;
        ut.s = addr;
        return ut.d;
    }

    bool Distanceof(char *addr, char *addrStub)
    {
        std::ptrdiff_t diff = (addrStub >= addr) ? (addrStub - addr) : (addr - addrStub);
        if ((sizeof(addr) > NUM_4) && (((diff >> NUM_31) - 1) > 0)) {
            return true;
        }
        return false;
    }

    // LP64
    long m_pagesize;
    std::map<char *, FuncStub *> m_result;
};

void StubOperateLogToAuditLog(const std::string &detail);

} // namespace cdf::test
#endif
