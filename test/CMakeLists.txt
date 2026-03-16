# --------------------------
# Define usefull test macros
# --------------------------

set(OPENSSL_PATH ${CMAKE_DEPENDENCY_LIBDIR})

macro(add_cdf_test NAME)
  add_executable(${NAME} ${NAME}.cpp)
  target_link_libraries(${NAME} PRIVATE CDF::cdf Dependency::gtest Dependency::secure_c)
  add_test(NAME ${NAME} COMMAND ${NAME})
  set_tests_properties(
    ${NAME}
    PROPERTIES ENVIRONMENT "OPENSSL_PATH=${OPENSSL_PATH};\
LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH")
endmacro()

# --------------------------
# Declare CDF tests
# --------------------------

add_cdf_test(test_cdf_base)
add_cdf_test(test_cdf_cryption)
add_cdf_test(test_cdf_utils)
add_cdf_test(test_cdf_key_manager)
add_cdf_test(test_cdf_authorization)
add_cdf_test(test_cdf_authentication_jwt)
add_cdf_test(test_cdf_rand)
add_cdf_test(test_cdf_psk_manager)
# add_cdf_test(test_cdf_authentication_krb)
