#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

set -e

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 BUILD_DIR LIBRARY_PATH"
  exit 1
fi

SOURCE=$(pwd)
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

export LIBRARY_PATH=$2:$LIBRARY_PATH

# merge the headers with the implementation files
cp -R include/osquery "$SYNC_DIR"
find ./osquery | grep "\.h" | grep -v tests/ | grep -v tables/ | xargs -i cp --parents {} "$SYNC_DIR"
cp $BUILD_DIR/generated/utils_amalgamation.cpp "$SYNC_DIR/osquery/generated/"

# delete all of the old CMake files
find "$SYNC_DIR" -type f -name "CMakeLists.txt" -exec rm -f {} \;

# make the targets file
mkdir -p "$SYNC_DIR/code-analysis"
(cd "$SYNC_DIR/code-analysis" && SDK=True cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $SOURCE)
python tools/codegen/gentargets.py \
  -v $VERSION --sdk $VERSION \
  -i "$SYNC_DIR/code-analysis/compile_commands.json" \
  -o $SYNC_DIR/osquery \
  -s osquery

cp osquery.thrift "$SYNC_DIR/osquery/extensions"

# wrap it up in a tarball
(cd "$SYNC_DIR" && tar -zcf osquery-sync-$VERSION.tar.gz osquery)
echo "Generated $SYNC_DIR/osquery-sync-$VERSION.tar.gz"
