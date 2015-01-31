#!/bin/bash

# Copyright (c) 2014, Ruslan Baratov
# All rights reserved.

declare -a BLACKLIST=(
    "osquery/devtools/shell.cpp"
  )

for BL_ITEM in ${BLACKLIST[@]}; do
  if [[ "$@" == *"${BL_ITEM}"* ]]; then
    clang++ "$@"
    exit 0;
  fi
done

for x in "$@"; do
  if [ ! "${x}" == "-c" ]; then
    continue
  fi

  OUTPUT="`mktemp /tmp/clang-analyze.out.XXXXX`"
  BINARY="`mktemp /tmp/clang-analyze.bin.XXXXX`"

  # analyze
  clang++ --analyze "$@" -o "${BINARY}" 2> "${OUTPUT}"

  RESULT=0
  [ "$?" == 0 ] || RESULT=1
  [ -s "${OUTPUT}" ] && RESULT=1

  cat "${OUTPUT}";
  rm -f "${OUTPUT}"
  rm -f "${BINARY}"

  if [ "${RESULT}" == "1" ]; then
    exit 1;
  fi
done

# compile real code
clang++ "$@"
