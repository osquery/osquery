# -*- mode: cmake; -*-
# - osquery macro definitions
#
# Remove boilerplate code for linking the osquery core dependent libs
# compiling and handling static or dynamic (run time load) libs.

# osquery-specific helper macros
macro(SET_OSQUERY_COMPILE TARGET)
  set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS ${OS_COMPILE_FLAGS})
  set(OPTIONAL_FLAGS ${ARGN})
  list(LENGTH OPTIONAL_FLAGS NUM_OPTIONAL_FLAGS)
  if(${NUM_OPTIONAL_FLAGS} GREATER 0)
    set_target_properties(${TARGET} PROPERTIES COMPILE_FLAGS ${OPTIONAL_FLAGS})
  endif()
endmacro(SET_OSQUERY_COMPILE)

macro(ADD_OSQUERY_TEST TEST_NAME SOURCE)
  if(NOT DEFINED ENV{SKIP_TESTS})
    add_executable(${TEST_NAME} ${SOURCE})
    TARGET_OSQUERY_LINK_WHOLE(${TEST_NAME} libosquery_basic)
    target_link_libraries(${TEST_NAME} libosquery_additional)
    target_link_libraries(${TEST_NAME} gtest)
    target_link_libraries(${TEST_NAME} glog)
    set(OPTIONAL_FLAGS ${ARGN})
    SET_OSQUERY_COMPILE(${TEST_NAME} "${OPTIONAL_FLAGS}")
    add_test(${TEST_NAME} ${TEST_NAME})
  endif()
endmacro(ADD_OSQUERY_TEST)

# Core/non core link helping macros (tell the build to link ALL).
macro(ADD_OSQUERY_LINK LINK)
  list(APPEND OSQUERY_ADDITIONAL_LINKS ${LINK})
  set(OSQUERY_ADDITIONAL_LINKS ${OSQUERY_ADDITIONAL_LINKS} PARENT_SCOPE)
endmacro(ADD_OSQUERY_LINK)

macro(ADD_OSQUERY_CORE_LINK LINK)
  list(APPEND OSQUERY_LINKS ${LINK})
  set(OSQUERY_LINKS ${OSQUERY_LINKS} PARENT_SCOPE)
endmacro(ADD_OSQUERY_CORE_LINK)

# Core/non core lists of target source files.
macro(ADD_OSQUERY_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET})
  list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_ADDITIONAL_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_LIBRARY TARGET)

macro(ADD_OSQUERY_CORE_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET})
  list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_CORE_LIBRARY TARGET)

# Core/non core lists of target source files compiled as ObjC++.
macro(ADD_OSQUERY_OBJCXX_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET} "${OBJCXX_COMPILE_FLAGS}")
  list(APPEND OSQUERY_ADDITIONAL_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_ADDITIONAL_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_OBJCXX_LIBRARY TARGET)

macro(ADD_OSQUERY_CORE_OBJCXX_LIBRARY TARGET)
  add_library(${TARGET} OBJECT ${ARGN})
  SET_OSQUERY_COMPILE(${TARGET} "${OBJCXX_COMPILE_FLAGS}")
  list(APPEND OSQUERY_SOURCES $<TARGET_OBJECTS:${TARGET}>)
  set(OSQUERY_SOURCES ${OSQUERY_SOURCES} PARENT_SCOPE)
endmacro(ADD_OSQUERY_CORE_OBJCXX_LIBRARY TARGET)

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
macro(GENERATE_TABLES TABLES_PATH BASE_PATH)
  # Get all matching files for all platforms.
  file(GLOB TABLE_FILES "${TABLES_PATH}/specs/x/*.table")
  set(TABLE_FILES_PLATFORM "")
  if(APPLE)
    file(GLOB TABLE_FILES_PLATFORM "${TABLES_PATH}/specs/darwin/*.table")
  elseif(FREEBSD)
    file(GLOB TABLE_FILES_PLATFORM "${TABLES_PATH}/specs/freebsd/*.table")
  else()
    file(GLOB TABLE_FILES_PLATFORM "${TABLES_PATH}/specs/linux/*.table")
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

macro(GENERATE_UTILITY TABLE_NAME)
  set(TABLE_SPEC "${CMAKE_SOURCE_DIR}/osquery/tables/specs/x/${TABLE_NAME}.table")
  set_property(GLOBAL APPEND PROPERTY AMALGAMATE_TARGETS "${TABLE_SPEC}")
endmacro()

macro(GENERATE_TABLE TABLE_FILE NAME BASE_PATH OUTPUT)
  set(TABLE_FILE_GEN ${TABLE_FILE})
  string(REPLACE ".table" ".cpp" TABLE_FILE_GEN ${TABLE_FILE_GEN})
  string(REPLACE "linux/" "" TABLE_FILE_GEN ${TABLE_FILE_GEN})
  string(REPLACE "darwin/" "" TABLE_FILE_GEN ${TABLE_FILE_GEN})
  string(REPLACE "freebsd/" "" TABLE_FILE_GEN ${TABLE_FILE_GEN})
  string(REPLACE "x/" "" TABLE_FILE_GEN ${TABLE_FILE_GEN})
  string(REGEX REPLACE
    ".*/specs"
    "${CMAKE_BINARY_DIR}/generated/tables_${NAME}"
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
endmacro()

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
endmacro()
