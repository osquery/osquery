ADD_EXECUTABLE(example_test example_test.cpp)
TARGET_LINK_LIBRARIES(example_test gtest)
SET_TARGET_PROPERTIES(example_test PROPERTIES COMPILE_FLAGS "-std=c++11 -stdlib=libc++")
ADD_TEST(example_test example_test)
