ADD_LIBRARY(osquery_scheduler OBJECT
  ../scheduler.h
  scheduler.cpp
)

SET_OSQUERY_COMPILE(osquery_scheduler)
