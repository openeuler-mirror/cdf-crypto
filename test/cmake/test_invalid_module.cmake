list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../../cmake")
include(ResolveModules)

set(ENABLE_MODULES "cert")
cdf_resolve_modules(REQUESTED AUTO_ENABLED EFFECTIVE)
