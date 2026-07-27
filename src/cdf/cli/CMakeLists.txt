add_executable(
  crypto_tool
  ${CMAKE_CURRENT_LIST_DIR}/cmd.cpp
  ${CMAKE_CURRENT_LIST_DIR}/config_handler.cpp
  ${CMAKE_CURRENT_LIST_DIR}/cryption_tool.cpp
  ${CMAKE_CURRENT_LIST_DIR}/kmc_cmd.cpp)

cdf_apply_project_options(crypto_tool)

target_compile_options(crypto_tool PRIVATE -fvisibility=hidden)

target_link_libraries(crypto_tool PUBLIC CDF::cdf Dependency::secure_c)

# Add -pie for the Release executable only.
target_link_options(crypto_tool PRIVATE "$<$<CONFIG:Release>:-pie>")

target_include_directories(
  crypto_tool
  PRIVATE "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>"
          "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
target_include_directories(crypto_tool SYSTEM PRIVATE
  ${CMAKE_DEPENDENCY_INCLUDEDIR})

install(TARGETS crypto_tool
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
install(FILES "${CMAKE_SOURCE_DIR}/config/crypto_tool_config.json"
  DESTINATION config
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ)
