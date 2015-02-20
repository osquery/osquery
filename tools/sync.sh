  #!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

if [[ "$#" < 1 ]]; then
  echo "Usage: $0 BUILD_DIR"
  exit 1
fi

BUILD_DIR=$1
SYNC_DIR="$BUILD_DIR/sync"
VERSION=`git describe --tags HEAD --always`

if [[ -f "$BUILD_DIR/sdk/generated" ]]; then
  echo "Error: $BUILD_DIR/sdk/generated not found."
  echo "Run 'make sdk' first"
  exit 1
fi

mkdir -p "$SYNC_DIR"
rm -rf "$SYNC_DIR/osquery*"

# merge the headers with the implementation files
cp -R osquery "$SYNC_DIR"
cp -R include/osquery "$SYNC_DIR"
cp -R "$BUILD_DIR/sdk/generated/" "$SYNC_DIR/osquery"
cp osquery.thrift "$SYNC_DIR/osquery/extensions"

# delete all of the old CMake files
find "$SYNC_DIR" -type f -name "CMakeLists.txt" -exec rm -f {} \;

# make the targets file
mkdir -p "$SYNC_DIR/code-analysis"
(cd "$SYNC_DIR/code-analysis" && SDK=True cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../../../)
python tools/codegen/gentargets.py -i "$SYNC_DIR/code-analysis/compile_commands.json" >$SYNC_DIR/osquery/TARGETS

# wrap it up in a tarball
(cd "$SYNC_DIR" && tar -zcf osquery-sync-$VERSION.tar.gz osquery)
echo "Generated $SYNC_DIR/osquery-sync-$VERSION.tar.gz"
