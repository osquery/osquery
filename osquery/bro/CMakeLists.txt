ADD_OSQUERY_LIBRARY(TRUE osquery_bro
        BrokerManager.cpp
        QueryManager.cpp
        utils.cpp
        )

file(GLOB OSQUERY_BRO_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_BRO_TESTS})