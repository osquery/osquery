# libbpf library build notes

`libbpf` is the standard library for interacting with BPF programs.

## Initialization

To add the submodule for `libbpf`, run the following from the osquery root:

```sh
git submodule add https://github.com/libbpf/libbpf.git libraries/cmake/source/libbpf/src
```

## Configuration

The `CMakeLists.txt` is configured to build `libbpf` as a static library. It depends on `thirdparty_libelf` and `thirdparty_zlib`.

### Build details

It uses the sources from the `src/src` directory of the submodule.
It also includes UAPI headers from `src/include/uapi`.
