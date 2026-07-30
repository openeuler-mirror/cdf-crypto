if(NOT DEFINED KRB5_ACLOCAL_FILE OR KRB5_ACLOCAL_FILE STREQUAL "")
  message(FATAL_ERROR "KRB5_ACLOCAL_FILE must name the krb5 aclocal.m4 file")
endif()
if(NOT EXISTS "${KRB5_ACLOCAL_FILE}")
  message(FATAL_ERROR "krb5 aclocal.m4 does not exist: ${KRB5_ACLOCAL_FILE}")
endif()

set(old_policy
    "error=incompatible-pointer-types error=discarded-qualifiers error=implicit-int")
set(new_policy
    "error=incompatible-pointer-types discarded-qualifiers error=implicit-int")

file(READ "${KRB5_ACLOCAL_FILE}" aclocal_contents)
string(REGEX MATCHALL "${old_policy}" old_matches "${aclocal_contents}")
string(REGEX MATCHALL "${new_policy}" new_matches "${aclocal_contents}")
list(LENGTH old_matches old_match_count)
list(LENGTH new_matches new_match_count)

if(old_match_count EQUAL 1 AND new_match_count EQUAL 0)
  string(REPLACE "${old_policy}" "${new_policy}" aclocal_contents
                 "${aclocal_contents}")
  file(WRITE "${KRB5_ACLOCAL_FILE}" "${aclocal_contents}")
elseif(NOT old_match_count EQUAL 0 OR NOT new_match_count EQUAL 1)
  message(FATAL_ERROR
          "krb5 aclocal.m4 does not contain the expected warning policy")
endif()
