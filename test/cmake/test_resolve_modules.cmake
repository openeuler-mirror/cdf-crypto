list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../../cmake")
include(ResolveModules)

function(reset_module_options)
  set(ENABLE_MODULES "" PARENT_SCOPE)
  set(ENABLE_ALL_MODULES OFF PARENT_SCOPE)
  foreach(module IN LISTS CDF_SUPPORTED_MODULES)
    string(TOUPPER "${module}" module_upper)
    set("ENABLE_MODULE_${module_upper}" OFF PARENT_SCOPE)
  endforeach()
endfunction()

function(assert_list_equals actual_variable expected)
  if(NOT "${${actual_variable}}" STREQUAL "${expected}")
    message(FATAL_ERROR
      "${actual_variable}: expected '${expected}', got '${${actual_variable}}'")
  endif()
endfunction()

function(assert_module_closure module expected_automatic expected_effective)
  reset_module_options()
  set(ENABLE_MODULES "${module}")
  cdf_resolve_modules(REQUESTED AUTO_ENABLED EFFECTIVE)
  assert_list_equals(REQUESTED "${module}")
  assert_list_equals(AUTO_ENABLED "${expected_automatic}")
  assert_list_equals(EFFECTIVE "${expected_effective}")
endfunction()

assert_module_closure(rand "" "rand")
assert_module_closure(cryption "rand" "cryption;rand")
assert_module_closure(key_management "cryption;rand"
  "cryption;key_management;rand")
assert_module_closure(authentication "cryption;key_management;rand"
  "authentication;cryption;key_management;rand")
assert_module_closure(authorization "" "authorization")
assert_module_closure(cli_tool "cryption;key_management;rand"
  "cli_tool;cryption;key_management;rand")
assert_module_closure(psk_management "cryption;key_management;rand"
  "cryption;key_management;psk_management;rand")

reset_module_options()
set(ENABLE_MODULE_RAND ON)
cdf_resolve_modules(REQUESTED AUTO_ENABLED EFFECTIVE)
assert_list_equals(REQUESTED "rand")
assert_list_equals(AUTO_ENABLED "")
assert_list_equals(EFFECTIVE "rand")

reset_module_options()
cdf_resolve_modules(REQUESTED AUTO_ENABLED EFFECTIVE)
assert_list_equals(REQUESTED
  "authentication;authorization;cli_tool;cryption;key_management;psk_management;rand")
assert_list_equals(AUTO_ENABLED "")
assert_list_equals(EFFECTIVE
  "authentication;authorization;cli_tool;cryption;key_management;psk_management;rand")

message(STATUS "module resolver tests passed")
