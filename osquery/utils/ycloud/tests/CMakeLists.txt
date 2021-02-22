# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsYCloudTestsMain)
    generateOsqueryUtilsYCloudTestsYCloudTest()
endfunction()

function(generateOsqueryUtilsYCloudTestsYCloudTest)
    add_osquery_executable(osquery_utils_ycloud_tests-test ycloud.cpp)

    target_link_libraries(osquery_utils_ycloud_tests-test PRIVATE
            osquery_cxx_settings
            osquery_core
            osquery_extensions
            osquery_extensions_implthrift
            osquery_registry
            osquery_utils_ycloud
            tests_helper
            thirdparty_googletest
            thirdparty_boost
            )
endfunction()

osqueryUtilsYCloudTestsMain()