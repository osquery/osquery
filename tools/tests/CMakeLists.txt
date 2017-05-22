# List of python modules containing unittests
ADD_OSQUERY_PYTHON_TEST(test_osqueryi test_osqueryi.py)
ADD_OSQUERY_PYTHON_TEST(test_osqueryd test_osqueryd.py)
ADD_OSQUERY_PYTHON_TEST(test_extensions test_extensions.py)
ADD_OSQUERY_PYTHON_TEST(test_additional test_additional.py)
ADD_OSQUERY_PYTHON_TEST(test_example_queries test_example_queries.py)

# If the build hosts are building release packages
if(DEFINED ENV{RUN_RELEASE_TESTS})
  ADD_OSQUERY_PYTHON_TEST(test_release test_release.py)
endif()
