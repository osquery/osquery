# Add the base file imported by tests
SYMLINK_FILE(${CMAKE_SOURCE_DIR}/osquery/python_tests/test_base.py ${CMAKE_BINARY_DIR}/osquery/python_tests/test_base.py)

ADD_OSQUERY_PYTHON_TEST(test_osqueryi test_osqueryi.py)
