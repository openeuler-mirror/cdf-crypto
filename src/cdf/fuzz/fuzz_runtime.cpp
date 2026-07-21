#include <cstdint>

#if defined(__GNUC__) || defined(__clang__)
#define CDF_FUZZ_WEAK __attribute__((weak))
#else
#define CDF_FUZZ_WEAK
#endif

// GCC's sanitizer-coverage instrumentation expects the fuzzing engine to
// provide these callbacks.  Weak defaults keep instrumented libraries
// linkable without a repository-specific harness; a real engine can override
// them with strong definitions.
extern "C" {
CDF_FUZZ_WEAK void __sanitizer_cov_trace_pc() {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_cmp1(std::uint8_t, std::uint8_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_cmp2(std::uint16_t, std::uint16_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_cmp4(std::uint32_t, std::uint32_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_cmp8(std::uint64_t, std::uint64_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_const_cmp1(std::uint8_t, std::uint8_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_const_cmp2(std::uint16_t, std::uint16_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_const_cmp4(std::uint32_t, std::uint32_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_const_cmp8(std::uint64_t, std::uint64_t) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_cmpf(float, float) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_cmpd(double, double) {}
CDF_FUZZ_WEAK void __sanitizer_cov_trace_switch(std::uint64_t, std::uint64_t *) {}
}

#undef CDF_FUZZ_WEAK
