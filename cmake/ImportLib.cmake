macro(import_static_lib_from LIBNAME LIB)
  add_library(${LIBNAME} STATIC IMPORTED)
  set_target_properties(
    ${LIBNAME}
    PROPERTIES
      IMPORTED_LOCATION
      ${CMAKE_DEPENDENCY_LIBDIR}/${LIBNAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
  add_dependencies(${LIBNAME} ${LIB})
endmacro()

macro(import_shared_lib_from LIBNAME LIB)
  add_library(${LIBNAME} SHARED IMPORTED)
  set_target_properties(
    ${LIBNAME}
    PROPERTIES
      IMPORTED_LOCATION
      ${CMAKE_DEPENDENCY_LIBDIR}/${LIBNAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
  add_dependencies(${LIBNAME} ${LIB})
endmacro()

macro(import_static_lib_from_exact_lib LIBNAME LIB)
  add_library(${LIBNAME} STATIC IMPORTED)
  set_target_properties(
    ${LIBNAME}
    PROPERTIES
      IMPORTED_LOCATION
      ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/lib/${LIBNAME}${CMAKE_STATIC_LIBRARY_SUFFIX}
  )
  add_dependencies(${LIBNAME} ${LIB})
endmacro()

macro(import_shared_lib_from_exact_lib LIBNAME LIB)
  add_library(${LIBNAME} SHARED IMPORTED)
  set_target_properties(
    ${LIBNAME}
    PROPERTIES
      IMPORTED_LOCATION
      ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/lib/${LIBNAME}${CMAKE_SHARED_LIBRARY_SUFFIX}
  )
  add_dependencies(${LIBNAME} ${LIB})
endmacro()
