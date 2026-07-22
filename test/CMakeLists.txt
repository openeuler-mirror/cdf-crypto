# --------------------------
# Define usefull test macros
# --------------------------

set(OPENSSL_PATH ${CMAKE_DEPENDENCY_LIBDIR})
string(REPLACE ";" "\\;" CDF_PARENT_LD_LIBRARY_PATH
       "$ENV{LD_LIBRARY_PATH}")
set(CDF_TEST_ENVIRONMENT
    "OPENSSL_PATH=${OPENSSL_PATH};LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:${CDF_PARENT_LD_LIBRARY_PATH}")

# --------------------------
# Declare CDF unit tests
# --------------------------
include(CMakeParseArguments)

function(cdf_add_unit_test name)
    set(multi_value_args SOURCES DEFINITIONS LIBRARIES)
    cmake_parse_arguments(CDF_TEST "" "" "${multi_value_args}" ${ARGN})

    add_executable(${name} ${CDF_TEST_SOURCES})
    cdf_apply_project_options(${name})
    target_include_directories(${name} PRIVATE
        "${PROJECT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/support"
    )
    target_link_libraries(${name} PRIVATE
        CDF::cdf
        Dependency::gtest
        Dependency::secure_c
        ${CDF_TEST_LIBRARIES}
    )
    if(CDF_TEST_DEFINITIONS)
        target_compile_definitions(${name} PRIVATE ${CDF_TEST_DEFINITIONS})
    endif()

    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT "${CDF_TEST_ENVIRONMENT}"
        LABELS "unit"
    )
endfunction()

cdf_add_unit_test(cdf_ut_base_utils SOURCES
    unit/base/test_base.cpp
    unit/utils/test_utils.cpp
)

if(ENABLE_MODULE_KEY_MANAGEMENT OR ENABLE_MODULE_AUTHENTICATION OR
   ENABLE_MODULE_PSK_MANAGEMENT OR ENABLE_ALL_MODULES)
    add_library(cdf_test_support STATIC support/test_utils.cpp)
    cdf_apply_project_options(cdf_test_support)
    target_include_directories(cdf_test_support PUBLIC
        "${PROJECT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/support"
    )
    target_link_libraries(cdf_test_support PUBLIC
        CDF::cdf
        Dependency::gtest
        Dependency::secure_c
    )
endif()

if(ENABLE_MODULE_CRYPTION OR ENABLE_ALL_MODULES)
    cdf_add_unit_test(cdf_ut_cryption SOURCES
        unit/modules/cryption/test_cryption.cpp
    )
endif()

if(ENABLE_MODULE_KEY_MANAGEMENT OR ENABLE_ALL_MODULES)
    cdf_add_unit_test(cdf_ut_key_management SOURCES
        unit/modules/key_management/test_key_manager.cpp
        unit/modules/key_management/test_km_cryptor.cpp
        LIBRARIES cdf_test_support
    )
endif()

if(ENABLE_MODULE_AUTHORIZATION OR ENABLE_ALL_MODULES)
    cdf_add_unit_test(cdf_ut_authorization SOURCES
        unit/modules/authorization/test_authorization.cpp
    )
endif()

if(ENABLE_MODULE_AUTHENTICATION OR ENABLE_ALL_MODULES)
    cdf_add_unit_test(cdf_ut_authentication_jwt SOURCES
        unit/modules/authentication/jwt/test_jwt.cpp
        LIBRARIES cdf_test_support
    )
    cdf_add_unit_test(cdf_ut_authentication_kerberos SOURCES
        unit/modules/authentication/kerberos/test_krb_ctx.cpp
    )
endif()

if(ENABLE_MODULE_RAND OR ENABLE_ALL_MODULES)
    cdf_add_unit_test(cdf_ut_rand SOURCES
        unit/modules/rand/test_rand.cpp
        DEFINITIONS CDF_RAND_TESTING
    )
endif()

if(ENABLE_MODULE_PSK_MANAGEMENT OR ENABLE_ALL_MODULES)
    cdf_add_unit_test(cdf_ut_psk_management SOURCES
        unit/modules/psk_management/test_psk_manager.cpp
        LIBRARIES cdf_test_support
    )
endif()

if(ENABLE_MODULE_CLI_TOOL OR ENABLE_ALL_MODULES)
    cdf_add_unit_test(cdf_ut_cli SOURCES
        unit/cli/test_config_handler.cpp
        unit/cli/test_cmd.cpp
        unit/cli/test_cryption_tool.cpp
        unit/cli/test_kmc_cmd.cpp
        ${PROJECT_SOURCE_DIR}/src/cdf/cli/cmd.cpp
        ${PROJECT_SOURCE_DIR}/src/cdf/cli/config_handler.cpp
        ${PROJECT_SOURCE_DIR}/src/cdf/cli/cryption_tool.cpp
        ${PROJECT_SOURCE_DIR}/src/cdf/cli/kmc_cmd.cpp
        DEFINITIONS __UNIT_TEST__
    )
endif()

if(ENABLE_MODULE_RAND OR ENABLE_ALL_MODULES)
    add_executable(deploy_verify_rand
        ${CMAKE_CURRENT_SOURCE_DIR}/integration/rand/deploy_verify_rand.cpp
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
        LABELS "integration"
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
