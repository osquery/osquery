#!/usr/bin/env python

import sys

filename = sys.argv[3]
findtext = sys.argv[1]
replacetext = sys.argv[2]

# Read in the file
with open(filename, 'r') as file:
  filedata = file.read()

# Replace the target string
filedata = filedata.replace(findtext, replacetext)

# Write the file out again
with open(filename, 'w') as file:
  file.write(filedata)
