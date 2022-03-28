# Creating tables

SQL tables are used to represent abstract operating system concepts, such as running processes.

A table can be used in conjunction with other tables via operations like sub-queries and joins. This allows for a rich data exploration experience. While osquery ships with a default set of tables, osquery provides an API that allows you to create new tables.

You can explore current schema here: [https://osquery.io/schema](https://osquery.io/schema/). Tables that are up for grabs in terms of development can be found on GitHub issues using the "virtual tables" + "[up for grabs tag](https://github.com/osquery/osquery/issues?q=is%3Aopen+is%3Aissue+label%3A%22virtual+tables%22)".

## New Table Walkthrough

Let's walk through an exercise where we build a 'time' table. The table will have one row, and that row will have three columns: hour, minute, and second.

Column values (a single row) will be dynamically computed at query time.

### Table specifications

Under the hood, osquery uses libraries from SQLite core to create "virtual tables". The default API for creating virtual tables is relatively complex. osquery has abstracted this complexity away, allowing you to write a simple table declaration.

To make table-creation simple, osquery uses a *table spec* file.
The current specs are organized by operating system in the [specs](https://github.com/osquery/osquery/tree/master/specs) source folder.
For our time exercise, a new spec file written to `./specs/time_example.table` would look like the following:

```python
# This .table file is called a "spec" and is written in Python
# This syntax (several definitions) is defined in /tools/codegen/gentable.py.
table_name("time_example")

# Provide a short "one line" description, please use punctuation!
description("Returns the current hour, minutes, and seconds.")

# Define your schema, which accepts a list of Column instances at minimum.
# You may also describe foreign keys and "action" columns.
schema([
    # Declare the name, type, and documentation description for each column.
    # The supported types are INTEGER, BIGINT, TEXT, DATE, and DATETIME.
    Column("hour", INTEGER, "The current hour"),
    Column("minutes", INTEGER, "The current minutes past the hour"),
    Column("seconds", INTEGER, "The current seconds past the minute"),
])

# Use the "@gen{TableName}" to communicate the C++ symbol name.
implementation("time@genTimeExample")
```

You can leave the comments out in your production spec. Shoot for simplicity, try to avoid things like inheritance for Column objects, loops in your table spec, etc.

You might wonder "this syntax looks similar to Python?" Well, it is! The build process actually parses the spec files as Python code and meta-programs necessary C/C++ implementation files.

### Where to put the spec

You may be wondering how osquery handles cross-platform support while still allowing operating-system specific tables. The osquery build process takes care of this by only generating the relevant code based on on logic in `./specs/CMakeLists.txt`. Additionally, we use a simple directory structure to help organize the many spec files.

- Cross-platform: [specs/](https://github.com/osquery/osquery/tree/master/specs/)
- macOS: [specs/darwin/](https://github.com/osquery/osquery/tree/master/specs/darwin)
- General Linux: [specs/linux/](https://github.com/osquery/osquery/tree/master/specs/linux)
- Windows: [specs/windows/](https://github.com/osquery/osquery/tree/master/specs/windows)
- POSIX: [specs/posix/](https://github.com/osquery/osquery/tree/master/specs/posix)
- You get the picture ;)

> NOTICE: the CMake build provides custom defines for each platform and platform version.

To make our new `time_example` work, find the function in `./specs/CMakeLists.txt` called `generateNativeTables` and add a line `time_example.table`.

### Specfile nuances

Each column in a **specfile** may have keyword arguments that effect how the SQLite behaves. If you require a column to be present in the `WHERE` predicate, like a `path` in the `file` table, then it must be reflected in the spec.

- **required=True**: This will create a warning if the table is used and the column does not appear in the predicate.
- **index=True**: This sets the `PRIMARY KEY` for the table, which helps the SQLite optimizer remove potential duplicates from complex `JOIN`s. If multiple columns have `index=True` then a primary key is created as the set of columns.
- **additional=True**: This is weird, but use **additional** if the presence of the column in the predicate would somehow alter the logic in the table generator. This tells SQLite not to optimize out any use of this column in the predicate.
- **hidden=True**: Sets the `HIDDEN` attribute for the column, so a `SELECT * FROM` will not include this column.

The table may also set `attributes`:

```python
attributes(user_data=True)
```

There are several attributes that help with table documentation and optimization. These are keyword arguments in the `attributes` optional method.

- **event_subscriber=True**: Indicates that the table is an abstraction on top of an event subscriber. The specfile for your subscriber must set this attribute.
- **user_data=True**: This tells the caller that they should provide a `uid` in the query predicate. By default the table will inspect the current user's content, but may be asked to include results from others.
- **cacheable=True**: The results from the table can be cached within the query schedule. If this table generates a lot of data it is best to cache the results so that queries needing access in the schedule with a shorter interval can simply copy the already generated structures.
- **utility=True**: This table will be included in the osquery SDK, it is considered a core/non-platform specific utility.

Specs may also include an **extended_schema** for a specific platform. They are the same as **schema** but the first argument is a function returning a bool. If true the columns are added and not marked hidden, otherwise they are all appended with `hidden=True`. This allows tables to keep a consistent set of columns and types while providing a good user experience for default selects.

### Creating your implementation

As indicated in the spec file, our implementation will be in a function called `genTimeExample`. Since this is a very general table and should compile on all supported operating systems we can place it in `./osquery/tables/utility/time_example.cpp`. The directory `./osquery/tables` contains the set of implementation categories. Each category *may* contain a platform-restricted directory. If a table requires a different implementation on different platform, use these subdirectories. Place implementations in the corresponding category using your best judgment. The appropriate `CMakeLists.txt` must define the files within the platform-related directory to know what to build.

Here is that code for `./osquery/tables/utility/time_example.cpp`:

```cpp
/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

QueryData genTimeExample(QueryContext &context) {
  QueryData rows;

  Row r;

  time_t _time = time(0);
  struct tm* now = localtime(&_time);

  r["hour"] = now->tm_hour;
  r["minutes"] = now->tm_min;
  r["seconds"] = now->tm_sec;

  rows.push_back(std::move(r));
  return rows;
}
}
}
```

And then edit `./osquery/tables/utility/CMakeLists.txt`, find the function `generateTablesUtilityUtilitytable` and add the new file `time_example.cpp` to list seen there.

Key points to remember:

- Your implementation function should be in the `osquery::tables` namespace.
- Your implementation function should accept on `QueryContext&` parameter and return an instance of `TableRows`.
- Your implementation function should use `context.isAnyColumnUsed` to run only the code necessary for the query.

### Adding an integration test

You may add small unit tests using GTest, but each table *should* have an integration test where the end-to-end selecting and checking data formats occurs.

Create a file `./tests/integration/tables/time_example.cpp`.

```cpp
/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/info/platform_type.h>

namespace osquery {
namespace table_tests {

class TimeExample : public testing::Test {
  protected:
    void SetUp() override {
      setUpEnvironment();
    }
};

TEST_F(TimeExample, test_sanity) {
  QueryData data = execute_query("select * from time_example");

  ASSERT_EQ(data.size(), 1ul);

  ValidationMap row_map = {
      {"hour", IntMinMaxCheck(0, 24)},
      {"minutes", IntMinMaxCheck(0, 59)},
      {"seconds", IntMinMaxCheck(0, 59)},
  };
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
```

Here you can see we are selecting from `time_example` and expecting exactly 1 row. We then place restrictions on the data in each column. There are a set of default checks that simple verify the data type, for example, `NonNegativeInt`, `NonEmptyString`, `NormalType`, ranging to more complex and specific checks. The [`helper.h`](https://github.com/osquery/osquery/tree/master/tests/integration/tables/helper.h) header classes and enumerations for checking validity. Please feel empowered to extend it.

To make this compile, open `./tests/integration/tables/CMakeLists.txt`, find the function `generateTestsIntegrationTablesTestsTest` and add `time_example.cpp`. You will need to configure CMake with `-DOSQUERY_BUILD_TESTS=ON` for the integration test to run. Please see the Building and [Testing](../building/#testing) documentation for more details.

## Using where clauses

The `QueryContext` data type is osquery's abstraction of the underlying SQL engine's query parsing. It is defined in `osquery/core/tables.h`.

The most important use of the context is query predicate constraints (e.g., `WHERE col = 'value'`). Some tables MUST have a predicate constraint, others may optionally use the constraints to increase performance.

Examples:

`hash` requires a predicate, since the resultant rows are the hashes of the EQUALS constraint operators (`=`). The table implementation includes:

```cpp
  auto paths = context.constraints["path"].getAll(EQUALS);
  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    [...]
  }
```

`processes` optionally uses a predicate. A syscall to list process PIDs requires few resources. Enumerating "/proc" information and parsing environment/argument uses MANY resources. The table implementation includes:

```cpp
  for (auto &pid : pidlist) {
    if (!context.constraints["pid"].matches<int>(pid)) {
      // Optimize by not searching when a pid is a constraint.
      continue;
    }
    [...]
  }
```

## SQL data types

Data types like `TableRows`, `TableRow`, `DiffResults`, etc. are osquery's built-in data result types. They're all defined in [osquery/database/database.h](https://github.com/osquery/osquery/blob/master/osquery/database/database.h).

`TableRow` is an interface; each table has a generated implementation with strongly-typed fields for each column in the table. There's also `DynamicTableRow`, which is backed by a `std::map<std::string, std::string>` mapping column names to the string representations of their values. `DynamicTableRow` exists to support tables that were written before the strongly-typed row support was added, and for plugins.

`TableRows` is just a `typedef` for a `std::vector<TableRow>`. Table rows is just a list of rows. Simple enough.

To populate the data that will be returned to the user at runtime, your implementation function must generate the data that you'd like to display and populate a `TableRows` list with the appropriate `TableRow`s. Then, just return the `TableRows`.

In our case, we used system APIs to create a struct of type `tm` which has fields such as `tm_hour`, `tm_min` and `tm_sec` which represent the current time. We can then set our three fields in our `TimeRow` variable: hour_col, minutes_col and seconds_col. Then we push that single row onto the `TableRows` variable and return it. Note that if we wanted our table to have many rows (a more common use-case), we would just push back more `TableRow` maps onto `results`.

### Testing your table

If your code compiled properly, launch the interactive query console by executing `./build/osquery/osqueryi` and try issuing your new table a command: `SELECT * FROM time;`. If your table implementation has nontrivial conditional code based on the columns used in the query, try issuing more focused commands to test that logic as well.

Run the leaks analysis to check for memory leaks:

```bash
./tools/analysis/profile.py --leaks --query "select * from time" --verbose
```

If your table parses content from the filesystem you should define fuzzing rules. In your table specification add:

```python
fuzz_paths([
    "/path/to/directory/used",
])
```

Then run `./tools/analysis/fuzz.py --table time`.

### Getting your query ready for use in osqueryd

You don't have to do anything to make your query work in the osqueryd daemon. All osquery queries work in osqueryd. It's worth noting, however, that osqueryd is a long-running process. If your table leaks memory or uses a lot of systems resources, you will notice poor performance from osqueryd. For more information on ensuring a performant table, see [performance overview](../deployment/performance-safety.md).

When in doubt, use existing open source tables to guide your development.
