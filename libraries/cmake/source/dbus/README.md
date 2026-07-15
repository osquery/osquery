# libdbus library build notes

## Linux

Integrate the osquery-toolchain, using the following file as a starting point: `cmake/toolchain.cmake`.

The in cmake/CMakeLists.txt remove the following lines:
```
  if(NOT EXPAT_FOUND)
      message(FATAL_ERROR "expat not found!")
  endif(NOT EXPAT_FOUND)
```

Then configure dbus with the following command:

```bash
cmake -S cmake -B b \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain \
  -DBUILD_SHARED_LIBS=OFF \
  -DDBUS_BUILD_TESTS=OFF \
  -DDBUS_ENABLE_VERBOSE_MODE=OFF \
  -DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF \
  -DCMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF \
  -DCMAKE_FIND_USE_CMAKE_SYSTEM_PATH=OFF \
  -DCMAKE_MAKE_PROGRAM=make \
```

NOTE: We disable system search paths so that the find_package calls do not find system libraries like X11 and Glib, since we don't want to build against those.

Patch the source code to make it build with the `dbus-noverbose-build.patch` file.

Then build libdbus only with:
```bash
cmake --build b --target dbus-1 --verbose
```

Always check which additional preprocessor defines are passed to the compiler.
Do not pass `-Ddbus_1_EXPORTS` but `-DBUS_STATIC_BUILD`.
We do not need to pass `--export-dynamic` (or `-rdynamic`), because the backtrace created by the assert already works;
we do need to pass `-DDBUS_BUILT_R_DYNAMIC` to get the backtrace though.

Copy the following generated files from the build folder:

`config.h` -> `config/<arch>/config.h`
`dbus/dbus-arch-deps.h` -> `generated/<arch>/dbus-arch-deps.h`

Finally in the `config.h` file substitute the path prefix `/usr/local/` with `/usr`, except for the paths that contain `/var`; in that case fully remove the `/usr/local` prefix, so that `/var` is at the root. This is needed because Dbus has to access files that on the system, not under some custom prefix.
