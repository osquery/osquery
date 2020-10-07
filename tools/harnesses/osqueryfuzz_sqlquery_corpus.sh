#!/usr/bin/env bash

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

set +e

# This script searches through most of osquery's source tree for sql-like statements to build
# a seed corpus.

# Something important to note about this script: it does NOT have to be perfect.
# If we output incomplete or malformed SQL statements because we extracted them
# incorrectly: that's okay. These results are used as a seed corpus, so they literally
# can be as malformed as possible and it doesn't matter.
# So we make a good effort to extract complete statements, but if it misses some, that's okay.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function usage() {
  echo "${BASH_SOURCE[0]} destination-file"
}

function main() {
  if [[ $# < 1 ]]; then
    usage
    exit 1
  fi

  # We put this above the current directory to avoid accidentally grabbing the file
  RESULTDEST=../tmp
  RESULTFILE=results.txt
  mkdir $RESULTDEST
  echo "" > $RESULTDEST/$RESULTFILE
  # Find all the files containing "select and pass them to this beast of an awk script
  # Only look in a few directories to avoid stuff like libraries, build, etc
  grep -R "\"select" $SCRIPT_DIR/../../tests $SCRIPT_DIR/../../packs $SCRIPT_DIR/../../osquery $SCRIPT_DIR/../../plugins -l | xargs -I [] -- awk '
function ltrim(s) { sub(/^[ \t\r\n]+/, "", s); return s }
function rtrim(s) { sub(/[ \t\r\n]+$/, "", s); return s }
function trim(s) { return rtrim(ltrim(s)); }
function remove_leading_json_key(s) { s=ltrim(s); sub(/^\"query\"[ \t]*:[ \t]*\"/, "", s); return s }
function remove_slash_continuance(s) { sub(/^\"/, "", s); sub(/\\$/, "", s); return s }
function remove_quote_continuance(s) { sub(/^\{?\"/, "", s); sub(/\"$/, "", s); return s }
function remove_statement_end(s) { sub(/[\"\)\];,]+$/, "", s); return s }
BEGIN {
}
# Reminder: strings are 1-indexed and match returns 0 on failure
# This block will be for matching what we hope will be a complete SQL string
# If it turns out it is not, we will test for two types of continuances below
/\"select(.+)/ {
# Look for a complete SQL statement, semicolon terminated, on one line ending in a quote
    i=match($0, /\"select(.+);\"$/);
    if(i) {
        print substr(remove_statement_end($0), i+1);
        next; # Were done, go to next line
    }
    # Look for hopefully a complete SQL statement on one line ending in a quote and then comma
    i=match($0, /\"select(.+)\",$/);
    if(i) {
        print substr(remove_statement_end($0), i+1);
        next; # Were done, go to next line
    }
}
# Okay, we did not find a sql statement with a semicolon or one ending in a ", so look for continuances
# This is a SQL statement that starts on one line and finishes with a line continuance: \
/\"select(.+)\\$/ {
    do {
        printf "%s", remove_slash_continuance(trim(remove_leading_json_key($0)));
        if(getline <= 0) # Tests for end of file
            break;
    } while( $0 ~ /(.+)\\$/ ); # As long as we keep finding lines ending in a \ keep printing it out
    print remove_statement_end($0);
    next;
}
# This is a SQL statement that starts on one line and finished with a C-style line continuance (a double-quote, no comma or +)
/^[ \t]*\{?\"select(.+)\"$/ {
    do {
        printf "%s", remove_quote_continuance(trim(remove_leading_json_key($0)));
        if(getline <= 0) # Tests for end of file
            break;
    } while( $0 ~ /(.+)\"$/ ); # As long as we keep finding lines ending in a " keep printing it out
    print remove_statement_end(remove_quote_continuance(trim($0)));
    next;
}
END {
}' [] >> $RESULTDEST/$RESULTFILE

  pushd $RESULTDEST

  # Find any \" and replace them with just "
  sed -i 's/\\\"/\"/g' $RESULTFILE

  # Okay we now have a file containing one SQL statement per line.
  # The corpus needs to be a zip file containing one statement per file.
  split -l 1 $RESULTFILE
  rm $RESULTFILE
  popd
  zip -j $1 $RESULTDEST/*
  rm -r $RESULTDEST
}

main $@
