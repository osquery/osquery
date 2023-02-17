# Unit testing in osquery

All commits to osquery should be well unit-tested. Having tests is useful for many reasons. In addition to the subtle advantage of being able to assert program correctness, tests are often the smallest possible executable which can run a given bit of code. This makes testing new features for memory leaks much easier. Using tools like Valgrind in conjunction with compiled tests, we can directly analyze the desired code with minimal outside influence.

## Writing a test

### Prerequisite

This guide is going to take you through the process of creating and building a new unit test in the osquery project.

First ensure that you can properly build the code, by referring to the ["building osquery"](building.md) guide.

Before you modify osquery code (or any code for that matter), make sure that you can successfully execute all tests. The steps for building and running tests are particular to the platform and build toolchain you are using, so again refer to the ["building osquery"](building.md) guide for the appropriate information for your setup.

## Adding a test

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

The above code is very simple. If you're unfamiliar with the syntax/concepts of the Google Test framework, read the [Google Test Primer](https://github.com/google/googletest/blob/master/googletest/docs/primer.md#basic-concepts).

## Building a test

Each component of osquery you're working on has its own "CMakeLists.txt" file. For example, the _tables_ component (folder) has its own "CMakeLists.txt" file at [osquery/tables/CMakeLists.txt](https://github.com/osquery/osquery/blob/master/osquery/tables/CMakeLists.txt). The file that we're going to be modifying today is [osquery/CMakeLists.txt](https://github.com/osquery/osquery/tree/master/osquery/CMakeLists.txt). Edit that file to include the following content:

```CMake
add_osquery_executable(example_test example_test.cpp)
```

After you specify the test sources, add whatever libraries you have to link against and properly set the compiler flags, make sure you call `ADD_TEST` with your unit test. This registers it with CTest (CMake's test runner).

## Extending a test

Your test is just C++ code. Use the [Google Test documentation](https://github.com/google/googletest/blob/master/googletest/docs/primer.md#assertions) to assist you in writing meaningful tests.
