#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# List of python modules containing unittests
if(NOT DEFINED ENV{SANITIZE})
  # Linenoise's input buffer fails TSAN checks.
  ADD_OSQUERY_PYTHON_TEST(test_osqueryi test_osqueryi.py)
endif()

ADD_OSQUERY_PYTHON_TEST(test_osqueryd test_osqueryd.py)
if(NOT WINDOWS)
  ADD_OSQUERY_PYTHON_TEST(test_additional test_additional.py)

  if(NOT DEFINED ENV{SANITIZE})
    # Too many FATAL's: failed to intercept strlen
    ADD_OSQUERY_PYTHON_TEST(test_extensions test_extensions.py)
    # The 'magic' table fails TSAN checks.
    ADD_OSQUERY_PYTHON_TEST(test_example_queries test_example_queries.py)
  endif()
endif()

# If the build hosts are building release packages
if(DEFINED ENV{RUN_RELEASE_TESTS})
  ADD_OSQUERY_PYTHON_TEST(test_release test_release.py)
endif()
