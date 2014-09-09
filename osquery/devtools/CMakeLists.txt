ADD_LIBRARY(osquery_devtools OBJECT
  ../devtools.h
  shell.cpp
)

SET_OSQUERY_COMPILE(osquery_devtools)
