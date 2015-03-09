All commits to osquery should be well unit-tested. Having tests is useful for many reasons. In addition to the subtle advantage of being able to assert program correctness, tests are often the smallest possible executable which can run a given bit of code. This makes testing new features for memory leaks much easier. Using tools like valgrind in conjunction with compiled tests, we can directly analyze the desired code with minimal outside influence.

## Writing a test

**Prerequisite**

This guide is going to take you through the process of creating and building a new unit test in the osquery project.

Ensure that you can properly build the code by running `make` at the root of the osquery repository. If your build fails, refer to the ["building the code"](https://github.com/facebook/osquery/wiki/building-the-code) guide.

Before you modify osquery code (or any code for that matter), make sure that you can successfully execute all tests. Run `make test` to run all tests.

**Adding a test**

We'll create a test in the "osquery/examples" subdirectory of the main repository. Let's create a file "example_test.cpp" in that directory.

Let's start with the following content:

```cpp
#include <gtest/gtest.h>

namespace osquery {
namespace example {

class ExampleTests : public testing::Test {};

TEST_F(ExampleTests, test_plugin) {
  EXPECT_TRUE(1 == 1);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
```

The above code is very simple. If you're unfamiliar with the syntax/concepts of the Google Test framework, read the [Google Test Primer](http://code.google.com/p/googletest/wiki/V1_7_Primer#Basic_Concepts).

## Building a test

Whatever component of osquery you're working on has it's own "CMakeLists.txt" file. For example, the _tables_ component (folder) has it's own "CMakeLists.txt"`" file at [osquery/tables/CMakeLists.txt](https://github.com/facebook/osquery/blob/master/osquery/tables/CMakeLists.txt). The file that we're going to be modifying today is [osquery/examples/CMakeLists.txt](https://github.com/facebook/osquery/tree/master/osquery/examples/CMakeLists.txt). Edit that file to include the following contents:

```CMake
ADD_OSQUERY_TEST(example_test example_test.cpp)
```

After you specify the test sources, add whatever libraries you have to link against and properly set the compiler flags, make sure you call `ADD_TEST` with your unit test. This registers it with CTest (CMake's test runner).

## Running a test

From the root of the repository run `make`. If you're code compiles properly, run `make test`. Ensure that your test has passed.

**Extending the test**

Your test is just C++ code. Use the [Google Test documentation](http://code.google.com/p/googletest/wiki/V1_7_Primer#Assertions) to assist you in writing meaningful tests.
