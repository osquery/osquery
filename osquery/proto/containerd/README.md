# Containerd Protocol Buffer Definitions

This directory contains Protocol Buffer (`.proto`) definitions for containerd's gRPC API, used by osquery's containerd tables on Linux.

## Version Information

- **API Version**: containerd v1 API (`/v1` services)
- **Source**: Official containerd API definitions from https://github.com/containerd/containerd
- **Compatible with**: containerd 1.6.x, 1.7.x, 2.0.x (v1 API is stable across versions)
- **Protocol Buffers**: proto3 syntax
- **gRPC Version**: v1.70.2 (see `libraries/cmake/source/grpc/`)

## Files

| File | Description | Service |
|------|-------------|---------|
| `containers.proto` | Container lifecycle management | `containerd.services.containers.v1.Containers` |
| `images.proto` | Image storage and metadata | `containerd.services.images.v1.Images` |
| `namespaces.proto` | Namespace isolation | `containerd.services.namespaces.v1.Namespaces` |
| `snapshots.proto` | Snapshot (filesystem layer) management | `containerd.services.snapshots.v1.Snapshots` |
| `tasks.proto` | Running container process management | `containerd.services.tasks.v1.Tasks` |

## Build Process

These `.proto` files are **source files** and are committed to git. The generated C++ code (`.pb.cc`, `.pb.h`, `.grpc.pb.cc`, `.grpc.pb.h`) is **generated at build time** and stored in the CMake build directory.

### Code Generation

Code generation is configured in `osquery/proto/CMakeLists.txt`:

1. **Protobuf compiler** (`protoc`) generates base message classes:
   - Input: `*.proto` files
   - Output: `*.pb.{h,cc}` files (in `${CMAKE_BINARY_DIR}/osquery/proto/containerd/`)

2. **gRPC plugin** (`grpc_cpp_plugin`) generates gRPC service stubs:
   - Input: `*.proto` files
   - Output: `*.grpc.pb.{h,cc}` files (in `${CMAKE_BINARY_DIR}/osquery/proto/containerd/`)

3. **Library target** `osquery_proto_containerd` links the generated code with `thirdparty_grpc`

### Include Path

The generated headers are included as:
```cpp
#include <containerd/containers.grpc.pb.h>
#include <containerd/images.grpc.pb.h>
#include <containerd/namespaces.grpc.pb.h>
#include <containerd/snapshots.grpc.pb.h>
#include <containerd/tasks.grpc.pb.h>
```

The `${CMAKE_BINARY_DIR}/osquery/proto/` directory is added to the include path, making `containerd/*.grpc.pb.h` available.

## Updating to a New Containerd Version

If you need to update these proto files to match a newer containerd version:

### Step 1: Identify Target Version

```bash
# Check containerd releases
git clone https://github.com/containerd/containerd.git /tmp/containerd
cd /tmp/containerd
git tag | grep -E "^v[0-9]+\.[0-9]+\.[0-9]+$" | tail -5
```

### Step 2: Extract Proto Files

```bash
# Checkout the target version
cd /tmp/containerd
git checkout v1.7.23  # or desired version

# Find the proto files (containerd uses internal api/ directory)
find api/services -name "*.proto" | grep -E "(containers|images|namespaces|snapshots|tasks)/v1"
```

Expected locations in containerd repo:
- `api/services/containers/v1/containers.proto`
- `api/services/images/v1/images.proto`
- `api/services/namespaces/v1/namespaces.proto`
- `api/services/snapshots/v1/snapshots.proto`
- `api/services/tasks/v1/tasks.proto`

### Step 3: Copy Proto Files

```bash
# Copy to osquery repo (assuming osquery repo is at $OSQUERY_ROOT)
cd $OSQUERY_ROOT
cp /tmp/containerd/api/services/containers/v1/containers.proto osquery/proto/containerd/
cp /tmp/containerd/api/services/images/v1/images.proto osquery/proto/containerd/
cp /tmp/containerd/api/services/namespaces/v1/namespaces.proto osquery/proto/containerd/
cp /tmp/containerd/api/services/snapshots/v1/snapshots.proto osquery/proto/containerd/
cp /tmp/containerd/api/services/tasks/v1/tasks.proto osquery/proto/containerd/
```

### Step 4: Add Copyright Headers

Add osquery copyright header to each file:
```proto
/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

syntax = "proto3";
// ... rest of proto file
```

### Step 5: Handle Proto Dependencies

Containerd proto files may import other proto files. Check for imports like:
```proto
import "google/protobuf/timestamp.proto";
import "containerd/types/descriptor.proto";
```

- **Standard imports** (e.g., `google/protobuf/*`): Already available from gRPC's bundled protobuf
- **Containerd-specific imports** (e.g., `containerd/types/*`): May need to copy additional files

If you see missing imports during build, copy the required `.proto` files from containerd's `api/types/` directory.

### Step 6: Update CMakeLists.txt (if needed)

If you added new proto files beyond the original 5, update `osquery/proto/CMakeLists.txt`:

```cmake
set(containerd_proto_files
  containers
  tasks
  namespaces
  images
  snapshots
  # Add new files here if needed
  # new_service
)
```

And add corresponding library sources:
```cmake
add_library(osquery_proto_containerd OBJECT
  ${CMAKE_CURRENT_BINARY_DIR}/containerd/containers.pb.cc
  ${CMAKE_CURRENT_BINARY_DIR}/containerd/containers.grpc.pb.cc
  # ... existing files ...
  # Add new generated files here
)
```

### Step 7: Test Build

```bash
# Clean build to regenerate proto files
rm -rf build
mkdir build && cd build
cmake -DOSQUERY_BUILD_TESTS=ON ..
cmake --build . -j$(nproc)
```

### Step 8: Update Implementation Code

Check if the new proto version introduces breaking changes:

1. **Message field changes**: Check if any fields were added/removed/renamed
2. **Service method changes**: Check if any RPC methods changed signatures
3. **Enum changes**: Check if any enum values changed

Update `osquery/tables/applications/linux/containerd.cpp` if needed.

### Step 9: Test Against Real Containerd

```bash
# Test against the target containerd version
sudo systemctl stop containerd
# Install new containerd version
sudo systemctl start containerd

# Run osquery tests
./build/osquery/osqueryd --disable_database --disable_events \
  --ephemeral --verbose \
  -S "SELECT * FROM containerd_containers"
```

### Step 10: Update This README

Update the version information at the top of this file:
- Update "Compatible with" version range
- Update gRPC version if changed
- Note any breaking changes or migration notes

### Step 11: Commit Changes

```bash
git add osquery/proto/containerd/*.proto
git add osquery/proto/containerd/README.md
git add osquery/proto/CMakeLists.txt  # if modified
git commit -m "Update containerd proto files to v1.7.23

- Updated proto definitions from containerd v1.7.23
- Compatible with containerd 1.7.x and 2.0.x
- No breaking changes in v1 API"
```

## API Stability

The containerd v1 API is considered **stable** and maintains backward compatibility:
- **v1 API**: Stable, no breaking changes across 1.x and 2.x releases
- **v2 API**: Not used by osquery (if it exists in future versions)

This means you can generally update proto files from any containerd 1.x or 2.x release without breaking osquery, as long as you only use the v1 services.

## Troubleshooting

### Build Error: "No rule to make target 'containerd/*.proto'"

**Cause**: Proto files missing or CMakeLists.txt not finding them.

**Fix**:
```bash
ls -la osquery/proto/containerd/*.proto  # Verify files exist
cd build && cmake ..  # Reconfigure CMake
```

### Build Error: "Unknown type 'google.protobuf.Timestamp'"

**Cause**: Missing protobuf import path.

**Fix**: Check that gRPC's protobuf include path is configured in CMakeLists.txt:
```cmake
-I ${CMAKE_SOURCE_DIR}/libraries/cmake/source/grpc/src/third_party/protobuf/src
```

### Runtime Error: "Unknown method" or "Unimplemented"

**Cause**: Version mismatch between proto files and running containerd daemon.

**Fix**:
1. Check containerd version: `containerd --version`
2. Verify proto files match that version
3. The v1 API should work across versions, but verify method exists in containerd source

### Proto Import Errors

**Cause**: Containerd proto files import other containerd types not yet copied.

**Fix**: Copy additional proto files from containerd's `api/types/` or `api/events/` directories as needed.

## References

- **containerd API source**: https://github.com/containerd/containerd/tree/main/api
- **containerd API docs**: https://github.com/containerd/containerd/blob/main/docs/api.md
- **gRPC C++ tutorial**: https://grpc.io/docs/languages/cpp/
- **Protocol Buffers**: https://protobuf.dev/
- **osquery containerd tables**: `osquery/tables/applications/linux/containerd.cpp`
