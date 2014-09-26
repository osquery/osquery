ADD_OSQUERY_LIBRARY(osquery_devtools
  shell.cpp
  printer.cpp
)

ADD_OSQUERY_TEST(printer_tests printer_tests.cpp)
