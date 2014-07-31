ADD_LIBRARY(osquery_sqlite
  sqlite3.c
)
TARGET_LINK_LIBRARIES(osquery_sqlite dl)
TARGET_LINK_LIBRARIES(osquery_sqlite pthread)
