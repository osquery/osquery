# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(toolsCodegenMain)
  # Prepare the gentable.py script
  generateGentable()
endfunction()

# Generates a runnable gentable.py script; unfortunately, upstream has scattered
# the required files around, so we need to piece them together
function(generateGentable)
  set(gentable_working_directory "${CMAKE_CURRENT_BINARY_DIR}/gentable")

  set(module_path "osquery/tools/tests")
  generatePythonModulePath("${gentable_working_directory}" "${module_path}" "gentable_dependency_")

  set(utils_file_path "${gentable_working_directory}/${module_path}/utils.py")
  add_custom_command(
    OUTPUT "${utils_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${CMAKE_SOURCE_DIR}/tools/tests/utils.py" "${utils_file_path}"
    DEPENDS "${generatePythonModulePath_rootTarget}"
  )

  add_custom_target("codegen_gentable_utils_dependency" DEPENDS "${utils_file_path}")

  set(gentable_file_path "${gentable_working_directory}/gentable.py")
  add_custom_command(
    OUTPUT "${gentable_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${CMAKE_CURRENT_SOURCE_DIR}/gentable.py" "${gentable_file_path}"
    DEPENDS "codegen_gentable_utils_dependency"
  )

  add_custom_target("codegen_gentable" DEPENDS "${gentable_file_path}")

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
    set(generated_code "${output_folder}/${table_name}.cpp")

    # Set up the generator
    get_filename_component(intermediate_directories "${generated_code}" DIRECTORY)

    if("${category}" STREQUAL "foreign")
      set(optional_foreign_parameter "--foreign")
    endif()

    add_custom_command(
      OUTPUT "${generated_code}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${intermediate_directories}"
      COMMAND "${CMAKE_COMMAND}" -E env "PYTHONPATH=${gentable_working_directory}" "${gentable_file_path}" ${optional_foreign_parameter} "${table_spec}" "${generated_code}"
      WORKING_DIRECTORY "${gentable_working_directory}"
      DEPENDS codegen_gentable "${table_spec}"
      COMMENT "Generating code for table ${category}/${table_name}..."
      VERBATIM
    )

    set(target_name "codegen_gentable_${category}_${table_name}")
    add_custom_target("${target_name}" DEPENDS "${generated_code}")

    list(APPEND generated_target_list "${target_name}")
  endforeach()

  # Return the base folder
  set(generateTables_output ${output_folder} PARENT_SCOPE)
  set(generateTables_targetList ${generated_target_list} PARENT_SCOPE)
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

  # Amalgamate all the source files into a single one
  set(amalgamation_file "${CMAKE_CURRENT_BINARY_DIR}/amalgamated_${category_name}_tables.cpp")

  if("${category_name}" STREQUAL "foreign")
    set(amalgamation_type "--foreign")
  else()
    set(amalgamation_type --category "${category_name}")
  endif()

  add_custom_command(
    OUTPUT "${amalgamation_file}"
    COMMAND "${CMAKE_SOURCE_DIR}/tools/codegen/amalgamate.py" --templates "${CMAKE_SOURCE_DIR}/tools/codegen/templates" ${amalgamation_type} --sources "${generateTables_output}" --output "${amalgamation_file}"
    COMMENT "Generating amalgamation file for the ${category_name} tables..."
    DEPENDS ${category_spec_files} ${generateTables_targetList}
  )

  # Build the library
  set(target_name "codegen_${category_name}_tables")

  add_library("${target_name}" EXCLUDE_FROM_ALL "${amalgamation_file}")
  target_link_libraries("${target_name}" PUBLIC osquery_events)

  # Return the target name to the caller
  set(generateTableCategoryAmalgamation_output "${target_name}" PARENT_SCOPE)
endfunction()

toolsCodegenMain()
