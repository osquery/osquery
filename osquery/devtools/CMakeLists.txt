ADD_OSQUERY_LIBRARY(FALSE osquery_devtools
  printer.cpp
)

ADD_OSQUERY_TEST(FALSE printer_tests printer_tests.cpp)