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

macro(LOG_PLATFORM NAME)
  LOG("Building for platform ${ESC}[36;1m${NAME} (${OSQUERY_BUILD_PLATFORM}, ${OSQUERY_BUILD_DISTRO})${ESC}[m")
  LOG("Building osquery version ${ESC}[36;1m ${OSQUERY_BUILD_VERSION} sdk ${OSQUERY_BUILD_SDK_VERSION}${ESC}[m")
endmacro(LOG_PLATFORM)

macro(LOG_LIBRARY NAME PATH)
  set(CACHE_NAME "LOG_LIBRARY_${NAME}")
  if(NOT DEFINED ${CACHE_NAME} OR NOT ${${CACHE_NAME}})
    set(${CACHE_NAME} TRUE CACHE BOOL "Write log line for ${NAME} library.")
    set(BUILD_POSITION -1)
    string(FIND "${PATH}" "${CMAKE_BINARY_DIR}" BUILD_POSITION)
    string(FIND "${PATH}" "NOTFOUND" NOTFOUND_POSITION)
    if(${NOTFOUND_POSITION} GREATER 0)
      WARNING_LOG("Could not find library: ${NAME}")
    else()
      if(${BUILD_POSITION} EQUAL 0)
        string(LENGTH "${CMAKE_BINARY_DIR}" BUILD_DIR_LENGTH)
        string(SUBSTRING "${PATH}" ${BUILD_DIR_LENGTH} -1 LIB_PATH)
        LOG("Found osquery-built library ${ESC}[32m${LIB_PATH}${ESC}[m")
      else()
        LOG("Found library ${ESC}[32m${PATH}${ESC}[m")
      endif()
    endif()
  endif()
endmacro(LOG_LIBRARY)

macro(ADD_OSQUERY_PYTHON_TEST TEST_NAME SOURCE)
  add_test(NAME python_${TEST_NAME}
    COMMAND ${PYTHON_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/tests/${SOURCE}"
      --build "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/tools/tests/")
endmacro(ADD_OSQUERY_PYTHON_TEST)

# Add a static or dynamic link to libosquery.a (the core library)
macro(ADD_OSQUERY_LINK_CORE LINK)
  ADD_OSQUERY_LINK(TRUE ${LINK} ${ARGN})
endmacro(ADD_OSQUERY_LINK_CORE)

# Add a static or dynamic link to libosquery_additional.a (the non-sdk library)
macro(ADD_OSQUERY_LINK_ADDITIONAL LINK)
  ADD_OSQUERY_LINK(FALSE ${LINK} ${ARGN})
endmacro(ADD_OSQUERY_LINK_ADDITIONAL)

# Core/non core link helping macros (tell the build to link ALL).
macro(ADD_OSQUERY_LINK IS_CORE LINK)
  if(${IS_CORE})
    ADD_OSQUERY_LINK_INTERNAL("${LINK}" "${ARGN}" OSQUERY_LINKS)
  elseif(NOT OSQUERY_BUILD_SDK_ONLY)
    ADD_OSQUERY_LINK_INTERNAL("${LINK}" "${ARGN}" OSQUERY_ADDITIONAL_LINKS)
  endif()
endmacro(ADD_OSQUERY_LINK)

macro(ADD_OSQUERY_LINK_INTERNAL LINK LINK_PATHS LINK_SET)
  set(LINK_PATHS "${CMAKE_BUILD_DIR}/third-party/*/lib"
    ${LINK_PATHS} /usr/lib /usr/local/lib "$ENV{HOME}")
  if(NOT "${LINK}" MATCHES "(^[-/].*)")
    string(REPLACE " " ";" ITEMS "${LINK}")
    foreach(ITEM ${ITEMS})
      if(NOT DEFINED ENV{BUILD_LINK_SHARED})
        find_library("${ITEM}_library" NAMES "lib${ITEM}.a" "${ITEM}" ${LINK_PATHS})
      else()
        find_library("${ITEM}_library" NAMES "lib${ITEM}.so" "lib${ITEM}.dylib" "${ITEM}" ${LINK_PATHS})
      endif()
      LOG_LIBRARY(${ITEM} "${${ITEM}_library}")
      if("${${ITEM}_library}" STREQUAL "${${ITEM}_library}-NOTFOUND")
        WARNING_LOG("Dependent library '${ITEM}' not found")
        list(APPEND ${LINK_SET} ${ITEM})
      else()
        list(APPEND ${LINK_SET} "${${ITEM}_library}")
      endif()
    endforeach()
  else()
    list(APPEND ${LINK_SET} ${LINK})
  endif()
  set(${LINK_SET} "${${LINK_SET}}" PARENT_SCOPE)
endmacro(ADD_OSQUERY_LINK_INTERNAL)

# Add a test and sources for components in libosquery.a (the core library)
macro(ADD_OSQUERY_TEST_CORE)
  ADD_OSQUERY_TEST(TRUE ${ARGN})
endmacro(ADD_OSQUERY_TEST_CORE)

# Add a test and sources for components in libosquery_additional.a (the non-sdk library)
macro(ADD_OSQUERY_TEST_ADDITIONAL)
  ADD_OSQUERY_TEST(FALSE ${ARGN})
endmacro(ADD_OSQUERY_TEST_ADDITIONAL)

# Core/non core test names and sources macros.
macro(ADD_OSQUERY_TEST IS_CORE)
  if(NOT DEFINED ENV{SKIP_TESTS} AND (${IS_CORE} OR NOT OSQUERY_BUILD_SDK_ONLY))
    if(${IS_CORE})
      list(APPEND OSQUERY_TESTS ${ARGN})
      set(OSQUERY_TESTS ${OSQUERY_TESTS} PARENT_SCOPE)
    else()
      list(APPEND OSQUERY_ADDITIONAL_TESTS ${ARGN})
      set(OSQUERY_ADDITIONAL_TESTS ${OSQUERY_ADDITIONAL_TESTS} PARENT_SCOPE)
    endif()
  endif()
endmacro(ADD_OSQUERY_TEST)

macro(ADD_OSQUERY_TABLE_TEST)
  if(NOT DEFINED ENV{SKIP_TESTS} AND NOT OSQUERY_BUILD_SDK_ONLY)
    list(APPEND OSQUERY_TABLES_TESTS ${ARGN})
    set(OSQUERY_TABLES_TESTS ${OSQUERY_TABLES_TESTS} PARENT_SCOPE)
  endif()
endmacro(ADD_OSQUERY_TABLE_TEST)

# Add kernel test macro.
macro(ADD_OSQUERY_KERNEL_TEST)
  if(NOT DEFINED ENV{SKIP_TESTS})
    list(APPEND OSQUERY_KERNEL_TESTS ${ARGN})
    set(OSQUERY_KERNEL_TESTS ${OSQUERY_KERNEL_TESTS} PARENT_SCOPE)
  endif()
endmacro(ADD_OSQUERY_KERNEL_TEST)

# Add sources to libosquery.a (the core library)
macro(ADD_OSQUERY_LIBRARY_CORE TARGET)
  ADD_OSQUERY_LIBRARY(TRUE ${TARGET} ${ARGN})
endmacro(ADD_OSQUERY_LIBRARY_CORE)

# Add sources to libosquery_additional.a (the non-sdk library)
macro(ADD_OSQUERY_LIBRARY_ADDITIONAL TARGET)
  ADD_OSQUERY_LIBRARY(FALSE ${TARGET} ${ARGN})
endmacro(ADD_OSQUERY_LIBRARY_ADDITIONAL)

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

# Add sources to libosquery.a (the core library)
macro(ADD_OSQUERY_OBJCXX_LIBRARY_CORE TARGET)
  ADD_OSQUERY_OBJCXX_LIBRARY(TRUE ${TARGET} ${ARGN})
endmacro(ADD_OSQUERY_OBJCXX_LIBRARY_CORE)

# Add sources to libosquery_additional.a (the non-sdk library)
macro(ADD_OSQUERY_OBJCXX_LIBRARY_ADDITIONAL TARGET)
  ADD_OSQUERY_OBJCXX_LIBRARY(FALSE ${TARGET} ${ARGN})
endmacro(ADD_OSQUERY_OBJCXX_LIBRARY_ADDITIONAL)

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
  if(NOT FREEBSD)
    target_link_libraries(${TARGET} dl)
  endif()
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
    "${BASE_PATH}/specs/blacklist"
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
    if(CENTOS OR RHEL OR AMAZON)
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
    COMMAND ${PYTHON_EXECUTABLE} "${BASE_PATH}/tools/codegen/gentable.py"
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
    COMMAND ${PYTHON_EXECUTABLE} "${BASE_PATH}/tools/codegen/amalgamate.py"
      "${BASE_PATH}/tools/codegen/" "${CMAKE_BINARY_DIR}/generated" "${NAME}"
    DEPENDS ${GENERATED_TARGETS} ${GENERATION_DEPENDENCIES}
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  set(${OUTPUT} "${CMAKE_BINARY_DIR}/generated/${NAME}_amalgamation.cpp")
endmacro(AMALGAMATE)

function(JOIN VALUES GLUE OUTPUT)
  string(REPLACE ";" "${GLUE}" _TMP_STR "${VALUES}")
  set(${OUTPUT} "${_TMP_STR}" PARENT_SCOPE)
endfunction(JOIN)
