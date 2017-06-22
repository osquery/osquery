SQL tables are used to represent abstract operating system concepts, such as running processes.

A table can be used in conjunction with other tables via operations like sub-queries and joins. This allows for a rich data exploration experience. While osquery ships with a default set of tables, osquery provides an API that allows you to create new tables.

You can explore current tables here: [https://osquery.io/tables](https://osquery.io/tables). Tables that are up for grabs in terms of development can be found on Github issues using the "virtual tables" + "[up for grabs tag](https://github.com/facebook/osquery/issues?q=is%3Aopen+is%3Aissue+label%3A%22virtual+tables%22)".

## New Table Walkthrough

Let's walk through an exercise where we build a 'time' table. The table will have one row, and that row will have three columns: hour, minute, and second.

Column values (a single row) will be dynamically computed at query time.

**Table specifications**

Under the hood, osquery uses libraries from SQLite core to create "virtual tables". The default API for creating virtual tables is relatively complex. osquery has abstracted this complexity away, allowing you to write a simple table declaration.

To make table-creation simple osquery uses a *table spec* file.
The current specs are organized by operating system in the [specs](https://github.com/facebook/osquery/tree/master/specs) source folder.
For our time exercise, a spec file would look like the following:

```python
# This .table file is called a "spec" and is written in Python
# This syntax (several definitions) is defined in /tools/codegen/gentable.py.
table_name("time")

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
implementation("time@genTime")
```

You can leave the comments out in your production spec. Shoot for simplicity, do NOT go "hard in the paint" and do things like inheritance for Column objects, loops in your table spec, etc.

You might wonder "this syntax looks similar to Python?". Well, it is! The build process actually parses the spec files as Python code and meta-programs necessary C/C++ implementation files.

**Where do I put the spec?**

You may be wondering how osquery handles cross-platform support while still allowing operating-system specific tables. The osquery build process takes care of this by only generating the relevant code based on a directory structure convention.

- Cross-platform: [specs/](https://github.com/facebook/osquery/tree/master/specs/)
- MacOS: [specs/darwin/](https://github.com/facebook/osquery/tree/master/specs/darwin)
- General Linux: [specs/linux/](https://github.com/facebook/osquery/tree/master/specs/linux)
- Windows: [specs/windows/](https://github.com/facebook/osquery/tree/master/specs/windows)
- POSIX: [specs/posix/](https://github.com/facebook/osquery/tree/master/specs/posix)
- FreeBSD: [specs/freebsd/](https://github.com/facebook/osquery/tree/master/specs/freebsd)
- You get the picture ;)

> NOTICE: the CMake build provides custom defines for each platform and platform version.

**Specfile nuances**

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
- **kernel_required=True**: This is rare, but tells the caller that results are only available if the osquery kernel extension is running.

Specs may also include an **extended_schema** for a specific platform. They are the same as **schema** but the first argument is a function returning a bool. If true the columns are added and not marked hidden, otherwise they are all appended with `hidden=True`. This allows tables to keep a consistent set of columns and types while providing a good user experience for default selects.

**Creating your implementation**

As indicated in the spec file, our implementation will be in a function called `genTime`. Since this is a very general table and should compile on all supported operating systems we can place it in *osquery/tables/utility/time.cpp*. The directory *osquery/table/* contains the set of implementation categories. Each category *may* contain a platform-restricted directory. If a table requires a different implementation on different platform, use these subdirectories. Place implementations in the corresponding category using your best judgment. CMake will discover all files within the platform-related directory at build time.

Here is that code for *osquery/tables/utility/time.cpp*:

```cpp
// Copyright 2004-present Facebook. All Rights Reserved.

#include <ctime>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genTime(QueryContext &context) {
  Row r;
  QueryData results;

  time_t _time = time(0);
  struct tm* now = localtime(&_time);

  r["hour"] = INTEGER(now->tm_hour);
  r["minutes"] = INTEGER(now->tm_min);
  r["seconds"] = INTEGER(now->tm_sec);

  results.push_back(r);
  return results;
}
}
}
```

Key points to remember:

- Your implementation function should be in the `osquery::tables` namespace.
- Your implementation function should accept on `QueryContext&` parameter and return an instance of `QueryData`.

## Using where clauses

The `QueryContext` data type is osquery's abstraction of the underlying SQL engine's query parsing. It is defined in [include/osquery/tables.h](https://github.com/facebook/osquery/blob/master/include/osquery/tables.h).

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

`processes` optionally uses a predicate. A syscall to list process pids requires few resources. Enumerating "/proc" information and parsing environment/argument uses MANY resources. The table implementation includes:
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

Data types like `QueryData`, `Row`, `DiffResults`, etc. are osquery's built-in data result types. They're all defined in [include/osquery/database.h](https://github.com/facebook/osquery/blob/master/include/osquery/database.h).

`Row` is just a `typedef` for a `std::map<std::string, std::string>`. That's it. A row of data is just a mapping of strings that represent column names to strings that represent column values. Note that, currently, even if your SQL table type is an `int` and not a `std::string`, we need to cast the ints as strings to comply with the type definition of the `Row` object. They'll be casted back to `int`s later. This is all handled transparently by osquery's supporting infrastructure as long as you use the macros like `TEXT`, `INTEGER`, `BIGINT`, etc. when inserting columns into your row.

`QueryData` is just a `typedef` for a `std::vector<Row>`. Query data is just a list of rows. Simple enough.

To populate the data that will be returned to the user at runtime, your implementation function must generate the data that you'd like to display and populate a `QueryData` map with the appropriate `Row`s. Then, just return the `QueryData`.

In our case, we used system APIs to create a struct of type `tm` which has fields such as `tm_hour`, `tm_min` and `tm_sec` which represent the current time. We can then create our three entries in our `Row` variable: hour, minutes and seconds. Then we push that single row onto the `QueryData` variable and return it. Note that if we wanted our table to have many rows (a more common use-case), we would just push back more `Row` maps onto `results`.

## Building new tables

If you've created a new **.{c,cpp,mm}** file in the correct folder within *osquery/tables*, CMake will discover and attempt to compile your implementation.

Return to the root of the repository and execute `make`. This will generate the appropriate code and link everything properly. If you need to add additional linking it gets a tad more complicated. Consider the following code within the table's [CMakeLists.txt](https://github.com/facebook/osquery/blob/master/osquery/tables/CMakeLists.txt):

```cmake

if(APPLE)
  # Add "-framework CoreFoundation" to the linker flags.
  ADD_OSQUERY_LINK_ADDITIONAL("-framework CoreFoundation")
  # Search for any library named magic
  ADD_OSQUERY_LINK_ADDITIONAL("magic")
elseif(FREEBSD)
  # Search for any library named magic
  ADD_OSQUERY_LINK_ADDITIONAL("magic")
else()
  # Search for any library named blkid
  ADD_OSQUERY_LINK_ADDITIONAL("blkid")
  # Search for the exact library name: libmagic.so
  ADD_OSQUERY_LINK_ADDITIONAL("libmagic.so")
endif()

```

This is a bit confusing but allows the table implementations to track three types of linking requests. The first is verbatim the linking flags needed for some tables; the second is a default search for static or shared library names; the final is the exact name of a library within the system's/build's configuration.

When supplying the "second type", a search name, CMake will decide to link using static or shared libraries based on environment settings. The cases where a shared library is ONLY allowed are usually related to that library being available by default on the operating system or platform.

### Testing your table

If your code compiled properly, launch the interactive query console by executing `./build/[darwin|linux]/osquery/osqueryi` and try issuing your new table a command: `SELECT * FROM time;`.

### Getting your query ready for use in osqueryd

You don't have to do anything to make your query work in the osqueryd daemon. All osquery queries work in osqueryd. It's worth noting, however, that osqueryd is a long-running process. If your table leaks memory or uses a lot of systems resources, you will notice poor performance from osqueryd. For more information on ensuring a performant table, see [performance overview](../deployment/performance-safety.md).

When in doubt, use existing open source tables to guide your development.
