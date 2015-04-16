# -*- mode: cmake; -*-
# - osquery macro definitions
#
# Remove boilerplate code for linking the osquery core dependent libs
# compiling and handling static or dynamic (run time load) libs.

# osquery-specific helper macros
macro(SET_OSQUERY_COMPILE TARGET)
  set(OPTIONAL_FLAGS ${ARGN})
  list(LENGTH OPTIONAL_FLAGS NUM_OPTIONAL_FLAGS)
  if(${NUM_OPTIONAL_FLAGS} GREATER 0)
    set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "${OPTIONAL_FLAGS}")
  endif()
endmacro(SET_OSQUERY_COMPILE)

macro(ADD_OSQUERY_TEST IS_CORE TEST_NAME SOURCE)
  if(NOT DEFINED ENV{SKIP_TESTS} AND (${IS_CORE} OR NOT OSQUERY_BUILD_SDK_ONLY))
    add_executable(${TEST_NAME} ${SOURCE})
    TARGET_OSQUERY_LINK_WHOLE(${TEST_NAME} libosquery)
    set(TEST_LINK_ADDITIONAL ${ARGN})
    if(NOT ${IS_CORE})
      target_link_libraries(${TEST_NAME} libosquery_additional)
    endif()
    target_link_libraries(${TEST_NAME} gtest libosquery_testing)
    SET_OSQUERY_COMPILE(${TEST_NAME} "${CXX_COMPILE_FLAGS} -DGTEST_HAS_TR1_TUPLE=0")
    add_test(${TEST_NAME} ${TEST_NAME})
  endif()
endmacro(ADD_OSQUERY_TEST)

macro(ADD_OSQUERY_PYTHON_TEST TEST_NAME SOURCE)
  add_test(NAME python_${TEST_NAME}
    COMMAND python "${CMAKE_SOURCE_DIR}/tools/tests/${SOURCE}" --build "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/tools/tests/")
endmacro(ADD_OSQUERY_PYTHON_TEST)

# Core/non core link helping macros (tell the build to link ALL).
macro(ADD_OSQUERY_LINK IS_CORE LINK)
  if(${IS_CORE})
    ADD_OSQUERY_LINK_INTERNAL("${LINK}" "${ARGN}" OSQUERY_LINKS)
  elseif(NOT OSQUERY_BUILD_SDK_ONLY)
    ADD_OSQUERY_LINK_INTERNAL("${LINK}" "${ARGN}" OSQUERY_ADDITIONAL_LINKS)
  endif()
endmacro(ADD_OSQUERY_LINK)

macro(ADD_OSQUERY_LINK_INTERNAL LINK LINK_PATHS LINK_SET)
  if(NOT "${LINK}" MATCHES "(^-.*)")
    find_library("${LINK}_library" NAMES "lib${LINK}.a" "${LINK}" ${LINK_PATHS})
    message("-- Found library dependency ${${LINK}_library}")
    if("${${LINK}_library}" STREQUAL "${${LINK}_library}-NOTFOUND")
      string(ASCII 27 Esc)
      message(WARNING "${Esc}[31mDependent library '${LINK}' not found${Esc}[m")
      list(APPEND ${LINK_SET} ${LINK})
    else()
      list(APPEND ${LINK_SET} "${${LINK}_library}")
    endif()
  else()
    list(APPEND ${LINK_SET} ${LINK})
  endif()
  set(${LINK_SET} "${${LINK_SET}}" PARENT_SCOPE)
endmacro(ADD_OSQUERY_LINK_INTERNAL)

# Core/non core lists of target source files.
macro(ADD_OSQUERY_LIBRARY IS_CORE TARGET)
  if(${IS_CORE} OR NOT OSQUERY_BUILD_SDK_ONLY)
    add_library(${TARGET} OBJECT ${ARGN})
    add_dependencies(${TARGET} libglog osquery_extensions)
    SET_OSQUERY_COMPILE(${TARGET} "${CXX_COMPILE_FLAGS} -static")
    if(${IS_CORE})
      list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
      set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
    else()
      list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
      set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_ADDITIONAL_SOURCES} PARENT_SCOPE)
    endif()
  endif()
endmacro(ADD_OSQUERY_LIBRARY TARGET)

# Core/non core lists of target source files compiled as ObjC++.
macro(ADD_OSQUERY_OBJCXX_LIBRARY IS_CORE TARGET)
  if(${IS_CORE} OR NOT OSQUERY_BUILD_SDK_ONLY)
    add_library(${TARGET} OBJECT ${ARGN})
    add_dependencies(${TARGET} libglog osquery_extensions)
    SET_OSQUERY_COMPILE(${TARGET} "${CXX_COMPILE_FLAGS} ${OBJCXX_COMPILE_FLAGS} -static")
    if(${IS_CORE})
      list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
      set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
    else()
      list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
      set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
    endif()
  endif()
endmacro(ADD_OSQUERY_OBJCXX_LIBRARY TARGET)

macro(ADD_OSQUERY_EXTENSION TARGET)
  add_executable(${TARGET} ${ARGN})
  TARGET_OSQUERY_LINK_WHOLE(${TARGET} libosquery)
  set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "${CXX_COMPILE_FLAGS}")
  set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${TARGET}.ext")
endmacro(ADD_OSQUERY_EXTENSION)

macro(ADD_OSQUERY_MODULE TARGET)
  add_library(${TARGET} SHARED ${ARGN})
  target_link_libraries(${TARGET} dl)
  add_dependencies(${TARGET} libglog libosquery)
  if(APPLE)
    target_link_libraries(${TARGET} "-undefined dynamic_lookup")
  endif()
  set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -fPIC")
  set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME ${TARGET})
endmacro(ADD_OSQUERY_MODULE)

# Helper to abstract OS/Compiler whole linking.
macro(TARGET_OSQUERY_LINK_WHOLE TARGET OSQUERY_LIB)
  target_link_libraries(${TARGET} "${OS_WHOLELINK_PRE}")
  target_link_libraries(${TARGET} ${OSQUERY_LIB})
  target_link_libraries(${TARGET} "${OS_WHOLELINK_POST}")
endmacro(TARGET_OSQUERY_LINK_WHOLE)

set(GLOBAL PROPERTY AMALGAMATE_TARGETS "")
macro(GET_GENERATION_DEPS BASE_PATH)
  # Depend on the generation code.
  set(GENERATION_DEPENDENCIES "")
  file(GLOB TABLE_FILES_TEMPLATES "${BASE_PATH}/osquery/tables/templates/*.in")
  set(GENERATION_DEPENDENCIES
    "${BASE_PATH}/tools/codegen/*.py"
    "${BASE_PATH}/osquery/tables/specs/blacklist"
  )
  list(APPEND GENERATION_DEPENDENCIES ${TABLE_FILES_TEMPLATES})
endmacro()

# Find and generate table plugins from .table syntax
macro(GENERATE_TABLES TABLES_PATH)
  # Get all matching files for all platforms.
  file(GLOB TABLE_FILES "${TABLES_PATH}/specs/*.table")
  set(TABLE_FILES_PLATFORM "")
  if(APPLE)
    file(GLOB TABLE_FILES_PLATFORM "${TABLES_PATH}/specs/darwin/*.table")
  elseif(FREEBSD)
    file(GLOB TABLE_FILES_PLATFORM "${TABLES_PATH}/specs/freebsd/*.table")
  else(LINUX)
    file(GLOB TABLE_FILES_PLATFORM "${TABLES_PATH}/specs/linux/*.table")
    if(CENTOS)
      file(GLOB TABLE_FILES_PLATFORM_FLAVOR "${TABLES_PATH}/specs/centos/*.table")
    elseif(UBUNTU)
      file(GLOB TABLE_FILES_PLATFORM_FLAVOR "${TABLES_PATH}/specs/ubuntu/*.table")
    endif()
    list(APPEND TABLE_FILES_PLATFORM ${TABLE_FILES_PLATFORM_FLAVOR})
  endif()
  list(APPEND TABLE_FILES ${TABLE_FILES_PLATFORM})

  get_property(TARGETS GLOBAL PROPERTY AMALGAMATE_TARGETS)
  set(NEW_TARGETS "")
  foreach(TABLE_FILE ${TABLE_FILES})
    list(FIND TARGETS "${TABLE_FILE}" INDEX)
    if (${INDEX} EQUAL -1)
      # Do not set duplicate targets.
      list(APPEND NEW_TARGETS "${TABLE_FILE}")
    endif()
  endforeach()
  set_property(GLOBAL PROPERTY AMALGAMATE_TARGETS "${NEW_TARGETS}")
endmacro()

macro(GENERATE_UTILITIES TABLES_PATH)
  file(GLOB TABLE_FILES_UTILITY "${TABLES_PATH}/specs/utility/*.table")
  set_property(GLOBAL APPEND PROPERTY AMALGAMATE_TARGETS "${TABLE_FILES_UTILITY}")
endmacro(GENERATE_UTILITIES)

macro(GENERATE_TABLE TABLE_FILE NAME BASE_PATH OUTPUT)
  set(TABLE_FILE_GEN ${TABLE_FILE})
  string(REGEX REPLACE
    ".*/specs.*/(.*)\\.table"
    "${CMAKE_BINARY_DIR}/generated/tables_${NAME}/\\1.cpp"
    TABLE_FILE_GEN
    ${TABLE_FILE_GEN}
  )

  GET_GENERATION_DEPS(${BASE_PATH})
  add_custom_command(
    OUTPUT "${TABLE_FILE_GEN}"
    COMMAND python "${BASE_PATH}/tools/codegen/gentable.py"
      "${TABLE_FILE}" "${TABLE_FILE_GEN}" "$ENV{DISABLE_BLACKLIST}"
    DEPENDS ${TABLE_FILE} ${GENERATION_DEPENDENCIES}
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  list(APPEND ${OUTPUT} "${TABLE_FILE_GEN}")
endmacro(GENERATE_TABLE)

macro(AMALGAMATE BASE_PATH NAME OUTPUT)
  GET_GENERATION_DEPS(${BASE_PATH})
  get_property(TARGETS GLOBAL PROPERTY AMALGAMATE_TARGETS)

  set(GENERATED_TARGETS "")
  foreach(TARGET ${TARGETS})
    GENERATE_TABLE(${TARGET} ${NAME} ${BASE_PATH} GENERATED_TARGETS)
  endforeach()

  # Include the generated folder in make clean.
  set_directory_properties(PROPERTY
    ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_BINARY_DIR}/generated")

  # Append all of the code to a single amalgamation.
  add_custom_command(
    OUTPUT "${CMAKE_BINARY_DIR}/generated/${NAME}_amalgamation.cpp"
    COMMAND python "${BASE_PATH}/tools/codegen/amalgamate.py"
      "${BASE_PATH}/osquery/tables/" "${CMAKE_BINARY_DIR}/generated" "${NAME}"
    DEPENDS ${GENERATED_TARGETS} ${GENERATION_DEPENDENCIES}
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  set(${OUTPUT} "${CMAKE_BINARY_DIR}/generated/${NAME}_amalgamation.cpp")
endmacro(AMALGAMATE)

function(JOIN VALUES GLUE OUTPUT)
  string(REPLACE ";" "${GLUE}" _TMP_STR "${VALUES}")
  set(${OUTPUT} "${_TMP_STR}" PARENT_SCOPE)
endfunction(JOIN)
