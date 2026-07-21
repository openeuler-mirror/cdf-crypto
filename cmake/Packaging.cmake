include_guard(GLOBAL)

macro(cdf_configure_packaging)
  set(CPACK_GENERATOR "RPM")
  set(CPACK_PACKAGE_NAME "cdf-crypto")
  set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
  set(CPACK_PACKAGE_RELOCATABLE NO)
  set(CPACK_RPM_USER_BINARY_SPECFILE "${PROJECT_BINARY_DIR}/cdf-crypto.spec")

  configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/StageCPackInstall.cmake.in"
    "${PROJECT_BINARY_DIR}/StageCPackInstall.cmake"
    @ONLY)
  install(SCRIPT "${PROJECT_BINARY_DIR}/StageCPackInstall.cmake")

  configure_file(
    "${PROJECT_SOURCE_DIR}/scripts/rpm/cdf-crypto.spec.in"
    "${PROJECT_BINARY_DIR}/cdf-crypto.spec"
    @ONLY)

  include(CPack)
endmacro()
