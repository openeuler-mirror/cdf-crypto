include_guard(GLOBAL)

set(CDF_SUPPORTED_MODULES
    authentication
    authorization
    cryption
    cli_tool
    key_management
    rand
    psk_management)

set(CDF_MODULE_DEPENDENCIES_authentication cryption key_management)
set(CDF_MODULE_DEPENDENCIES_authorization "")
set(CDF_MODULE_DEPENDENCIES_cryption rand)
set(CDF_MODULE_DEPENDENCIES_cli_tool cryption key_management)
set(CDF_MODULE_DEPENDENCIES_key_management cryption)
set(CDF_MODULE_DEPENDENCIES_rand "")
set(CDF_MODULE_DEPENDENCIES_psk_management cryption key_management rand)

function(cdf_module_option_name module output_variable)
  string(TOUPPER "${module}" module_upper)
  set(${output_variable} "ENABLE_MODULE_${module_upper}" PARENT_SCOPE)
endfunction()

function(cdf_list_contains list_variable value output_variable)
  list(FIND ${list_variable} "${value}" found_index)
  if(found_index EQUAL -1)
    set(${output_variable} OFF PARENT_SCOPE)
  else()
    set(${output_variable} ON PARENT_SCOPE)
  endif()
endfunction()

function(cdf_validate_module module)
  cdf_list_contains(CDF_SUPPORTED_MODULES "${module}" module_supported)
  if(NOT module_supported)
    string(JOIN ", " supported ${CDF_SUPPORTED_MODULES})
    message(FATAL_ERROR
      "Unknown CDF module '${module}'. Supported modules: ${supported}")
  endif()
endfunction()

function(cdf_resolve_modules requested_output automatic_output effective_output)
  set(requested "")
  set(select_all OFF)

  foreach(module IN LISTS ENABLE_MODULES)
    string(TOLOWER "${module}" normalized_module)
    if(normalized_module STREQUAL "all")
      set(select_all ON)
    elseif(NOT normalized_module STREQUAL "")
      cdf_validate_module("${normalized_module}")
      list(APPEND requested "${normalized_module}")
    endif()
  endforeach()

  if(ENABLE_ALL_MODULES)
    set(select_all ON)
  endif()

  foreach(module IN LISTS CDF_SUPPORTED_MODULES)
    cdf_module_option_name("${module}" option_name)
    if(DEFINED ${option_name} AND ${option_name})
      list(APPEND requested "${module}")
    endif()
  endforeach()

  if(select_all OR NOT requested)
    set(requested ${CDF_SUPPORTED_MODULES})
  endif()

  list(REMOVE_DUPLICATES requested)
  set(effective ${requested})
  set(changed ON)
  while(changed)
    set(changed OFF)
    set(current_modules ${effective})
    foreach(module IN LISTS current_modules)
      set(dependency_variable "CDF_MODULE_DEPENDENCIES_${module}")
      foreach(dependency IN LISTS ${dependency_variable})
        cdf_list_contains(effective "${dependency}" dependency_enabled)
        if(NOT dependency_enabled)
          list(APPEND effective "${dependency}")
          set(changed ON)
        endif()
      endforeach()
    endforeach()
  endwhile()

  list(REMOVE_DUPLICATES effective)
  set(automatic ${effective})
  foreach(module IN LISTS requested)
    list(REMOVE_ITEM automatic "${module}")
  endforeach()

  list(SORT requested)
  list(SORT automatic)
  list(SORT effective)

  foreach(module IN LISTS CDF_SUPPORTED_MODULES)
    cdf_module_option_name("${module}" option_name)
    cdf_list_contains(effective "${module}" module_enabled)
    if(module_enabled)
      set(${option_name} ON PARENT_SCOPE)
    else()
      set(${option_name} OFF PARENT_SCOPE)
    endif()
  endforeach()

  list(LENGTH effective effective_count)
  list(LENGTH CDF_SUPPORTED_MODULES supported_count)
  if(effective_count EQUAL supported_count)
    set(ENABLE_ALL_MODULES ON PARENT_SCOPE)
  else()
    set(ENABLE_ALL_MODULES OFF PARENT_SCOPE)
  endif()

  set(${requested_output} "${requested}" PARENT_SCOPE)
  set(${automatic_output} "${automatic}" PARENT_SCOPE)
  set(${effective_output} "${effective}" PARENT_SCOPE)
endfunction()
