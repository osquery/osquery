#!/bin/bash

# This script is meant to test that format-check.py and git-clang-format.py format all the files they should.

function usage {
  echo "Usage:"
  echo "format-test.sh --build <build directory>"
  echo "Run from the root of the source directory"
}
args=("$@")

if [ ! "${args[0]}" == "--build" ] || [ -z "${args[1]}" ]; then
  echo -e "Missing --build argument\n"
  usage
  exit 1
fi

build_dir=${args[1]}

set -e

# List all files to format, skipping all the ones inside the libraries folder, sort them and save the list on a file
find . -type d -path ./libraries -prune -o -type f -regex ".*\.cpp$\|.*\.h$\|.*\.hpp$\|.*\.mm$" -print | sort > $build_dir/files_to_format.txt

# Read back the list of files, modify them appending two newlines, so that the format_check.py is triggered
while read line; do echo -e "\n\n" >> $line; done <<< `cat $build_dir/files_to_format.txt`

# Run the format check, save the command output and invert the exit code, since finding formatting issues is what we want
! cmake --build $build_dir --target format_check > $build_dir/format_output.txt

# Print the command output previously saved
format_output=`cat $build_dir/format_output.txt`
echo "$format_output"

# Extract all the modified files from the output, sort them and save the list on a file
echo "$format_output" | grep "diff --git" | awk '{ print $3 }' | sed 's/^a/./g' | sort > $build_dir/formatted_files.txt

# Verify that the script formatted everything it should have
git diff --no-index $build_dir/files_to_format.txt $build_dir/formatted_files.txt

# Restore original source code
git reset --hard HEAD
