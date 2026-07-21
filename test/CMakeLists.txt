# --------------------------
# Define usefull test macros
# --------------------------

set(OPENSSL_PATH ${CMAKE_DEPENDENCY_LIBDIR})
string(REPLACE ";" "\\;" CDF_PARENT_LD_LIBRARY_PATH
       "$ENV{LD_LIBRARY_PATH}")
set(CDF_TEST_ENVIRONMENT
    "OPENSSL_PATH=${OPENSSL_PATH};LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:${CDF_PARENT_LD_LIBRARY_PATH}")

# --------------------------
# Declare CDF tests
# --------------------------
# Common tests that only depend on the CDF base and utility sources.
set(ALL_TEST_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_utils.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_base.cpp)

# Key-manager-aware helpers are only needed by tests for these modules.  Keep
# them out of independent module builds such as authorization-only.
if(ENABLE_MODULE_KEY_MANAGEMENT OR ENABLE_MODULE_AUTHENTICATION OR
   ENABLE_MODULE_PSK_MANAGEMENT OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_utils.cpp)
endif()

# Conditionally include module-specific tests
if(ENABLE_MODULE_CRYPTION OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_cryption.cpp)
endif()

if(ENABLE_MODULE_KEY_MANAGEMENT OR ENABLE_ALL_MODULES)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_key_manager.cpp)
    list(APPEND ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/test_cdf_km_cryptor.cpp)
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
cdf_apply_project_options(cdf_ut_test_all)
target_compile_definitions(cdf_ut_test_all PRIVATE CDF_RAND_TESTING)
target_link_libraries(cdf_ut_test_all PRIVATE
    CDF::cdf
    Dependency::gtest
    Dependency::secure_c
)

add_test(NAME cdf_ut_test_all COMMAND cdf_ut_test_all)

set_tests_properties(cdf_ut_test_all PROPERTIES
    ENVIRONMENT "${CDF_TEST_ENVIRONMENT}"
)

if(ENABLE_MODULE_RAND OR ENABLE_ALL_MODULES)
    add_executable(deploy_verify_rand
        ${CMAKE_CURRENT_SOURCE_DIR}/deploy_verify_rand.cpp
    )
    cdf_apply_project_options(deploy_verify_rand)
    target_link_libraries(deploy_verify_rand PRIVATE
        CDF::cdf
    )
    target_include_directories(deploy_verify_rand PRIVATE
        ${PROJECT_SOURCE_DIR}/src
    )
    add_test(NAME deploy_verify_rand COMMAND deploy_verify_rand)
    set_tests_properties(deploy_verify_rand PROPERTIES
        ENVIRONMENT "${CDF_TEST_ENVIRONMENT}"
    )
endif()

find_program(BASH_EXECUTABLE bash)
if(NOT BASH_EXECUTABLE)
    message(FATAL_ERROR "bash is required to run CDF build-system tests")
endif()

function(cdf_add_build_system_test name script)
    add_test(NAME ${name}
        COMMAND "${BASH_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/${script}")
    set_tests_properties(${name} PROPERTIES LABELS "build-system")
endfunction()

cdf_add_build_system_test(build_script_contract test/build_script_test.sh)
cdf_add_build_system_test(build_packaging_config
    test/cmake/test_packaging_config.sh)
cdf_add_build_system_test(build_target_scopes
    test/cmake/test_target_scopes.sh)
cdf_add_build_system_test(build_test_and_coverage_config
    test/cmake/test_test_and_coverage_config.sh)
cdf_add_build_system_test(build_copy_git_worktree
    test/cmake/test_copy_git_worktree.sh)
cdf_add_build_system_test(build_native_make_tool
    test/cmake/test_native_make_tool.sh)
set_tests_properties(build_native_make_tool PROPERTIES SKIP_RETURN_CODE 77)

add_test(NAME build_module_resolver
    COMMAND "${CMAKE_COMMAND}" -P
            "${PROJECT_SOURCE_DIR}/test/cmake/test_resolve_modules.cmake")
set_tests_properties(build_module_resolver PROPERTIES LABELS "build-system")
