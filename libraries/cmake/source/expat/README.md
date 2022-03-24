# Linux

Create a build folder inside the root of the cloned project and move inside it.

Generated with the following commands:

```sh
cmake ../expat -DCMAKE_BUILD_TYPE=Release \
-DEXPAT_BUILD_TOOLS=OFF \
-DEXPAT_BUILD_TESTS=OFF \
-DEXPAT_SHARED_LIBS=OFF \
-DEXPAT_BUILD_PKGCONFIG=OFF \
-DEXPAT_BUILD_EXAMPLES=OFF \
-DEXPAT_DTD=OFF \
-DEXPAT_NS=OFF \
-DEXPAT_DEV_URANDOM=OFF
```

Copy the following files:

build/expat_config.h -> \<osquery libexpat folder\>/config/
