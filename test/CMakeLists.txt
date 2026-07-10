# --------------------------
# Define usefull test macros
# --------------------------

set(OPENSSL_PATH ${CMAKE_DEPENDENCY_LIBDIR})

# --------------------------
# Declare CDF tests
# --------------------------
# Common test utilities (always included)
set(ALL_TEST_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/test_utils.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_utils.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_base.cpp)

# Conditionally include module-specific tests
if(ENABLE_MODULE_CRYPTION OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_cryption.cpp)
endif()

if(ENABLE_MODULE_KEY_MANAGEMENT OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_key_manager.cpp)
endif()

if(ENABLE_MODULE_AUTHORIZATION OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_authorization.cpp)
endif()

if(ENABLE_MODULE_AUTHENTICATION OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_authentication_jwt.cpp)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_authentication_krb.cpp)
endif()

if(ENABLE_MODULE_RAND OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_rand.cpp)
endif()

if(ENABLE_MODULE_PSK_MANAGEMENT OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_psk_manager.cpp)
endif()

add_executable(cdf_ut_test_all ${ALL_TEST_SOURCES})
target_compile_definitions(cdf_ut_test_all PRIVATE CDF_RAND_TESTING)
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
        LD_LIBRARY_PATH=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../lib64:${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH
        $<TARGET_FILE:cdf_ut_test_all> --gtest_output=xml:${PROJECT_SOURCE_DIR}/build/test_results.xml
        DEPENDS cdf_ut_test_all
)

if(ENABLE_MODULE_RAND OR ENABLE_ALL_MODULES)
    add_executable(deploy_verify_rand
        ${CMAKE_CURRENT_SOURCE_DIR}/deploy_verify_rand.cpp
    )
    target_link_libraries(deploy_verify_rand PRIVATE
        CDF::cdf
    )
    target_include_directories(deploy_verify_rand PRIVATE
        ${PROJECT_SOURCE_DIR}/src
    )
    add_test(NAME deploy_verify_rand COMMAND deploy_verify_rand)
    set_tests_properties(deploy_verify_rand PROPERTIES
        ENVIRONMENT "OPENSSL_PATH=${OPENSSL_PATH};LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH"
    )
endif()
