# libelf library build notes

`libelf` is required for `libbpf` and other BPF-related components in osquery.

## Initialization

To add the submodule for `libelf`, run the following from the osquery root:

```sh
git submodule add https://github.com/elfutils/elfutils.git libraries/cmake/source/libelf/src
```

Note: If a specific fork is required, adjust the URL accordingly.

## Configuration

The `CMakeLists.txt` is configured to build `libelf` as a static library. It expects the source code to be available in the `src` directory.

### Linux

Build notes for targeting the osquery toolchain:

```bash
export TOOLCHAIN=/usr/local/osquery-toolchain
export PATH="${TOOLCHAIN}/usr/bin:${PATH}"
export CFLAGS="--sysroot ${TOOLCHAIN}"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export CC=clang

# Adjust configure options as needed for the specific libelf implementation
./configure --enable-static --disable-shared
make
```
