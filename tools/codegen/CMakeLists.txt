# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(toolsCodegenMain)
  # Prepare the gentable.py script
  generateGentable()
endfunction()

# Generates a runnable gentable.py script; unfortunately, upstream has scattered
# the required files around, so we need to piece them together
function(generateGentable)
  set(module_path "osquery_tests/tools/tests")
  generatePythonModulePath("${OSQUERY_PYTHON_PATH}" "${module_path}" "osquery_pythonpath_")

  set(utils_file_path "${OSQUERY_PYTHON_PATH}/${module_path}/utils.py")
  add_custom_command(
    OUTPUT "${utils_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E copy "${CMAKE_SOURCE_DIR}/tools/tests/utils.py" "${utils_file_path}"
    DEPENDS "${generatePythonModulePath_rootTarget}"
  )

  add_custom_target("codegen_gentable_utils_dependency" DEPENDS "${utils_file_path}")

  set(gentable_working_directory "${CMAKE_CURRENT_BINARY_DIR}/gentable")
  generatePythonModulePath("${CMAKE_CURRENT_BINARY_DIR}" "gentable" "gentable_dependency_")
  set(gentable_file_path "${gentable_working_directory}/gentable.py")
  set(source_base_path "${CMAKE_CURRENT_SOURCE_DIR}")
  add_custom_command(
    OUTPUT "${gentable_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${source_base_path}/gentable.py" "${gentable_file_path}"
    DEPENDS "codegen_gentable_utils_dependency" "${generatePythonModulePath_rootTarget}"
  )

  set(templite_file_path "${gentable_working_directory}/templite.py")
  add_custom_command(
    OUTPUT "${templite_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${source_base_path}/templite.py" "${templite_file_path}"
    DEPENDS "codegen_gentable_utils_dependency" "${generatePythonModulePath_rootTarget}"
  )

  add_custom_target("codegen_gentable" DEPENDS "${gentable_file_path}" "${templite_file_path}")

  # Save the path in a property, so that we can reference it in the generateTables() function
  # when it is called from another scope
  set_property(GLOBAL PROPERTY CODEGEN_GENTABLE_PATH "${gentable_file_path}")
  set_property(GLOBAL PROPERTY CODEGEN_GENTABLE_WORKINGDIRECTORY "${gentable_working_directory}")
endfunction()

# This function generates a path in a similar way to `mkdir -p` while also creating
# a `__init__.py` file in each folder
function(generatePythonModulePath base_path path identifier)
  string(REPLACE "/" ";" path_components "${path}")

  set(current_base_path "${base_path}")
  set(index 1)

  foreach(component ${path_components})
    set(current_path "${current_base_path}/${component}")
    set(init_file_path "${current_path}/__init__.py")

    add_custom_command(
      OUTPUT "${init_file_path}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${current_path}"
      COMMAND "${CMAKE_COMMAND}" -E touch "${init_file_path}"
    )

    set(target_name "${identifier}_generator_${index}")
    add_custom_target("${target_name}" DEPENDS "${init_file_path}")
    list(APPEND target_list "${target_name}")

    set(current_base_path "${current_path}")
    math(EXPR index "${index}+1")
  endforeach()

  set(root_target "${identifier}_generator")
  add_custom_target("${root_target}")

  set(previous_target "${root_target}")
  list(REVERSE target_list)

  foreach(target ${target_list})
    add_dependencies("${previous_target}" "${target}")
    set(previous_target "${target}")
  endforeach()

  set(generatePythonModulePath_rootTarget "${root_target}" PARENT_SCOPE)
endfunction()

# Generates the table code from a list of table spec files
function(generateTables category)
  # Acquire the gentable path and working directory from the global properties (set from
  # generateGentable())
  get_property(gentable_file_path GLOBAL PROPERTY CODEGEN_GENTABLE_PATH)
  get_property(gentable_working_directory GLOBAL PROPERTY CODEGEN_GENTABLE_WORKINGDIRECTORY)

  if("${gentable_file_path}" STREQUAL "")
    message(SEND_ERROR "The gentable.py tool was not found!")
    return()
  endif()

  if("${gentable_working_directory}" STREQUAL "")
    message(SEND_ERROR "The gentable.py working directory was not found!")
    return()
  endif()

  # Make sure we actually have parameters
  if(${ARGC} EQUAL 1)
    message(SEND_ERROR "No spec file specified")
    return()
  endif()

  # Convert all relative paths to absolute paths
  foreach(relative_table_spec ${ARGN})
    list(APPEND table_spec_list "${CMAKE_SOURCE_DIR}/specs/${relative_table_spec}")
  endforeach()

  # Iterate through each table spec file
  set(output_folder "${CMAKE_CURRENT_BINARY_DIR}/${category}")

  foreach(table_spec ${table_spec_list})
    # Use the file name as table name
    get_filename_component(table_name "${table_spec}" NAME_WE)
    set(generated_source_code "${output_folder}/${table_name}.cpp")

    set(generated_headers_folder "${output_folder}/osquery/rows")
    set(generated_header_code "${generated_headers_folder}/${table_name}.h")

    # Set up the generator
    get_filename_component(source_code_intermediate_directories "${generated_source_code}" DIRECTORY)

    if("${category}" STREQUAL "foreign")
      set(optional_foreign_parameter "--foreign")
    endif()

    add_custom_command(
      OUTPUT "${generated_source_code}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${source_code_intermediate_directories}"
      COMMAND "${CMAKE_COMMAND}" -E env "PYTHONPATH=${OSQUERY_PYTHON_PATH}" "${OSQUERY_PYTHON_EXECUTABLE}" "${gentable_file_path}" --templates "${CMAKE_SOURCE_DIR}/tools/codegen/templates" ${optional_foreign_parameter} "${table_spec}" "${generated_source_code}"
      WORKING_DIRECTORY "${gentable_working_directory}"
      DEPENDS codegen_gentable "${table_spec}"
      COMMENT "Generating code for table ${category}/${table_name}..."
      VERBATIM
    )

    add_custom_command(
      OUTPUT "${generated_header_code}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${generated_headers_folder}"
      COMMAND "${CMAKE_COMMAND}" -E env "PYTHONPATH=${OSQUERY_PYTHON_PATH}" "${OSQUERY_PYTHON_EXECUTABLE}" "${gentable_file_path}" --header --templates "${CMAKE_SOURCE_DIR}/tools/codegen/templates" ${optional_foreign_parameter} "${table_spec}" "${generated_header_code}"
      WORKING_DIRECTORY "${gentable_working_directory}"
      DEPENDS codegen_gentable "${table_spec}"
      COMMENT "Generating header for table ${category}/${table_name}..."
      VERBATIM
    )

    set(table_target_name "codegen_gentable_${category}_${table_name}")
    add_custom_target("${table_target_name}" DEPENDS "${generated_source_code}")

    set(header_generator_target_name "codegen_gentable_${category}_${table_name}_header")
    add_custom_target("${header_generator_target_name}" DEPENDS "${generated_header_code}")

    set(header_library_name "osquery_rows_${table_name}_header")
    add_osquery_library("${header_library_name}" INTERFACE)
    add_dependencies("${header_library_name}" "${header_generator_target_name}")
    target_include_directories("${header_library_name}" INTERFACE "${output_folder}")

    list(APPEND generated_sources_list
      "${generated_source_code}"
    )
  endforeach()

  # Workaround for the fact that if we disable a table after having made a build with such table,
  # the specific table .cpp is not removed from the build folder and will be picked up
  # by the amalgamate.py, causing a linker error.
  # CMake + Ninja doesn't have this issue, since Ninja contains a command to automatically delete
  # all artifacts that are not generated in the current configuration, and such command is automatically
  # called by CMake during configure time.
  file(GLOB generated_table_sources_on_disk "${output_folder}/*.cpp")

  foreach(generated_source ${generated_table_sources_on_disk})
    if(NOT "${generated_source}" IN_LIST generated_sources_list)
      file(REMOVE "${generated_source}")
    endif()
  endforeach()

  # Return the base folder
  set(generateTables_output ${output_folder} PARENT_SCOPE)
  set(generateTables_outputList ${generated_sources_list} PARENT_SCOPE)
endfunction()

function(generateTableCategoryAmalgamation category_name)
  # Make sure we actually have parameters
  if(${ARGC} EQUAL 1)
    message(SEND_ERROR "No spec file specified")
    return()
  endif()

  set(category_spec_files ${ARGN})

  # Generate the source files
  generateTables("${category_name}" ${category_spec_files})

  # Workaround for the fact that CMake and the underlying build systems
  # do not consider a change in the list of dependencies as a reason to rerun the custom command,
  # if the inputs are not also directly used in the COMMAND, which then causes a command line change.
  set(amalgamation_dep_list_file "${CMAKE_CURRENT_BINARY_DIR}/amalgamation_${category_name}_dep_list.txt")
  if(EXISTS "${amalgamation_dep_list_file}")
    set(tmp_amalgamation_dep_list_file "${CMAKE_CURRENT_BINARY_DIR}/amalgamation_${category_name}_dep_list.txt.tmp")
    file(WRITE "${tmp_amalgamation_dep_list_file}" "${generateTables_outputList}")
    file(SHA256 "${tmp_amalgamation_dep_list_file}" tmp_amalgamation_dep_list_file_sha)
    file(SHA256 "${amalgamation_dep_list_file}" amalgamation_dep_list_file_sha)

    if(NOT "${amalgamation_dep_list_file_sha}" STREQUAL "${tmp_amalgamation_dep_list_file_sha}")
      file(RENAME "${tmp_amalgamation_dep_list_file}" "${amalgamation_dep_list_file}")
    else()
      file(REMOVE "${tmp_amalgamation_dep_list_file}")
    endif()
  else()
    file(WRITE "${amalgamation_dep_list_file}" "${generateTables_outputList}")
  endif()

  list(TRANSFORM category_spec_files PREPEND "${CMAKE_SOURCE_DIR}/specs/")

  # Amalgamate all the source files into a single one
  set(amalgamation_file "${CMAKE_CURRENT_BINARY_DIR}/amalgamated_${category_name}_tables.cpp")

  if("${category_name}" STREQUAL "foreign")
    set(amalgamation_type "--foreign")
  else()
    set(amalgamation_type --category "${category_name}")
  endif()

  list(APPEND amalgamate_deps
    ${amalgamation_dep_list_file}
    ${generateTables_outputList}
  )

  add_custom_command(
    OUTPUT "${amalgamation_file}"
    COMMAND "${CMAKE_COMMAND}" -E env "PYTHONPATH=${OSQUERY_PYTHON_PATH}" "${OSQUERY_PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/codegen/amalgamate.py" --templates "${CMAKE_SOURCE_DIR}/tools/codegen/templates" ${amalgamation_type} --sources "${generateTables_output}" --output "${amalgamation_file}"
    COMMENT "Generating amalgamation file for the ${category_name} tables..."
    DEPENDS ${amalgamate_deps}
  )

  # Build the library
  set(target_name "codegen_${category_name}_tables")

  add_osquery_library("${target_name}" EXCLUDE_FROM_ALL "${amalgamation_file}")
  target_link_libraries("${target_name}" PUBLIC osquery_events)

  # Return the target name to the caller
  set(generateTableCategoryAmalgamation_output "${target_name}" PARENT_SCOPE)
endfunction()

toolsCodegenMain()
