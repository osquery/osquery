# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsYCloudMain)
    if(OSQUERY_BUILD_TESTS)
        add_subdirectory("tests")
    endif()

    generateOsqueryUtilsYCloud()
endfunction()

function(generateOsqueryUtilsYCloud)
    add_osquery_library(osquery_utils_ycloud EXCLUDE_FROM_ALL
            ycloud_util.cpp
            )

    target_link_libraries(osquery_utils_ycloud PUBLIC
            osquery_cxx_settings
            osquery_remote_httpclient
            osquery_remote_transports_transportstls
            osquery_utils_json
            osquery_utils_status
            )

    set(public_header_files
            ycloud_util.h
            )

    generateIncludeNamespace(osquery_utils_ycloud "osquery/utils/ycloud" "FILE_ONLY" ${public_header_files})

    add_test(NAME osquery_utils_ycloud_tests-test COMMAND osquery_utils_ycloud_tests-test)

    set_tests_properties(
            osquery_utils_ycloud_tests-test
            PROPERTIES ENVIRONMENT "TEST_CONF_FILES_DIR=${TEST_CONFIGS_DIR}"
    )
endfunction()

osqueryUtilsYCloudMain()
