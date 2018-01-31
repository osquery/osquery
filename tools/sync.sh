  #!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

set -e

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 BUILD_DIR"
  exit 1
fi

BUILD_DIR=$1
SYNC_DIR="$BUILD_DIR/sync"
VERSION=`git describe --tags HEAD --always`

if [ -f "$BUILD_DIR/generated" ]; then
  echo "Error: $BUILD_DIR/generated not found."
  echo "Run 'make sdk' first"
  exit 1
fi

mkdir -p "$SYNC_DIR"
rm -rf "$SYNC_DIR/osquery*"
mkdir -p "$SYNC_DIR/osquery/generated"

# merge the headers with the implementation files
cp -R osquery "$SYNC_DIR"
cp -R include/osquery "$SYNC_DIR"
for file in $BUILD_DIR/generated/*.cpp; do
  cp "$file" "$SYNC_DIR/osquery/generated/";
done
cp osquery.thrift "$SYNC_DIR/osquery/extensions"
rm -rf "$SYNC_DIR/osquery/examples"

# delete all of the old CMake files
find "$SYNC_DIR" -type f -name "CMakeLists.txt" -exec rm -f {} \;

# make the targets file
mkdir -p "$SYNC_DIR/code-analysis"
(cd "$SYNC_DIR/code-analysis" && SDK=True cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../../../../)
python tools/codegen/gentargets.py -v $VERSION --sdk $VERSION \
  -i "$SYNC_DIR/code-analysis/compile_commands.json" >$SYNC_DIR/osquery/TARGETS

# wrap it up in a tarball
(cd "$SYNC_DIR" && tar -zcf osquery-sync-$VERSION.tar.gz osquery)
echo "Generated $SYNC_DIR/osquery-sync-$VERSION.tar.gz"
