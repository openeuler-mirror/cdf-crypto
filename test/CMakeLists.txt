# --------------------------
# Define usefull test macros
# --------------------------

set(OPENSSL_PATH ${CMAKE_DEPENDENCY_LIBDIR})

# --------------------------
# Declare CDF tests
# --------------------------
file(GLOB_RECURSE ALL_TEST_SOURCES
        test_utils.cpp
        test_cdf_cryption.cpp
        test_cdf_utils.cpp
        test_cdf_key_manager.cpp
        test_cdf_authorization.cpp
        test_cdf_authentication_jwt.cpp
        test_cdf_rand.cpp
        test_cdf_psk_manager.cpp)

# Add common test utilities
list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_utils.cpp)

add_executable(cdf_ut_test_all ${ALL_TEST_SOURCES})
target_link_libraries(cdf_ut_test_all PRIVATE
    CDF::cdf
    Dependency::gtest
    Dependency::secure_c
)

add_test(NAME cdf_ut_test_all COMMAND cdf_ut_test_all)

set_tests_properties(cdf_ut_test_all PROPERTIES
    ENVIRONMENT "OPENSSL_PATH=${OPENSSL_PATH};LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH"
)

add_custom_target(build_test
        COMMAND env
        LD_PRELOAD=/usr/lib/gcc/aarch64-openEuler-linux/12/libasan.so
        LD_LIBRARY_PATH=${PROJECT_SOURCE_DIR}/output/cdf/lib64:${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH
        ${PROJECT_SOURCE_DIR}/build/bin/cdf_ut_test_all --gtest_output=xml:${PROJECT_SOURCE_DIR}/build/test_results.xml
        DEPENDS
)
