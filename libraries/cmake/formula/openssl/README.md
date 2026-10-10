# openssl library build notes

OpenSSL is built through its own `Configure` script and makefiles, which CMake
drives as an external project (see `CMakeLists.txt` in this folder). The
release archive is downloaded from GitHub, or taken from
`OSQUERY_OPENSSL_ARCHIVE_PATH` if that option is set.

## Configure options

Only `libssl` and `libcrypto` are used by osquery, so the build disables what
it does not need:

- `no-tests`, `no-apps`: the OpenSSL test suite and the `openssl` program.
  OpenSSL disables its tests along with its apps, which the tests drive.
- `no-docs`: the manual pages.

## Updating OpenSSL

1. Set `OPENSSL_VERSION` and `OPENSSL_ARCHIVE_SHA256` in `CMakeLists.txt`.
   Check the hash against the `openssl-<version>.tar.gz.sha256` file published
   with the release.
2. Update the `openssl` entry in `libraries/third_party_libraries_manifest.json`.
3. Optionally, run the OpenSSL test suite with osquery's build options, as
   described below.

## Running the OpenSSL test suite

The osquery build never runs the OpenSSL tests. To run them, for example when
updating OpenSSL, configure a separate build directory with
`OSQUERY_OPENSSL_BUILD_TESTS` enabled and build the `openssl-test` target:

```sh
cmake -S . -B build-openssl-tests -DOSQUERY_OPENSSL_BUILD_TESTS=ON
cmake --build build-openssl-tests --target openssl
cmake --build build-openssl-tests --target openssl-test
```

This builds the tests and the `openssl` program in addition to the libraries,
then runs `make test` (`nmake test` on Windows) in the OpenSSL source folder.
The libraries are built with the same options as in a normal build.

OpenSSL's test harness variables can be passed through the environment, e.g.
`HARNESS_JOBS=8` to run tests in parallel, `TESTS=test_x509` to run a subset,
or `V=1` for verbose output.

### Expected failures

Tests that load one of OpenSSL's dynamically loaded provider modules fail,
because osquery compiles OpenSSL with `-fvisibility=hidden`, which hides the
`OSSL_provider_init` entry point of those modules. These include tests of the
legacy provider (e.g. `test_enc`, `test_enc_more`, `test_pbe`, `test_pkcs8`)
and of the test provider (`test_provider`, `test_internal_provider`).
osquery only uses the providers built into `libcrypto` and does not load
provider modules, so these failures do not affect it.

Review any other failures before updating.
