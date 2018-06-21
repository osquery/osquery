#!/bin/bash
set -e

BUILD_DIR=$1
CMAKE_COMMAND="$2 -G Xcode"

echo "Cleanup build dir:$BUILD_DIR"
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

echo "Generating xcode project using cmake: $CMAKE_COMMAND"
cd ${BUILD_DIR} 
eval ${CMAKE_COMMAND}

echo "Fixing cmake quotes around \$(inherited)"
sed -i -e "s/'\$(inherited)'/\$(inherited)/g" ./OSQUERY.xcodeproj/project.pbxproj
