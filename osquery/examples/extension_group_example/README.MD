All the extensions made with the **add_osquery_extension_ex()** CMake function will be automatically bundled into a single executable.

The executable name and version can be changed using the following two environment variables:

1. OSQUERY_EXTENSION_GROUP_NAME
2. OSQUERY_EXTENSION_GROUP_VERSION

It is important to provide a header file that can be included by the generated main.cpp file; its purpose is to define the required classes used by the **REGISTER_EXTERNAL** directive.

