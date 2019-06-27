#!/usr/bin/env python2

import sys
import urllib
import hashlib

def main(argc, argv):
  if argc != 4:
    print "Usage:\n\t%s https://url/to/file.txt /path/to/destination/file.txt <expected_sha256_hash>" % (argv[0])
    return 1

  url = argv[1]
  destination_file = argv[2]
  expected_hash = argv[3]

  try:
    print "Downloading..."
    url_opener = urllib.URLopener()
    url_opener.retrieve(url, destination_file)

  except:
    print "Failed to retrieve the file from the given url"
    return 1

  print "Verifying the file hash..."
  file_hash = get_file_hash(destination_file)
  if file_hash == None:
    print "Failed to compute the file hash"
    return 1

  if file_hash <> expected_hash:
    print "The downloaded file seems to be corrupted"
    return 1

  print "The file has been successfully downloaded!"
  return 0

def get_file_hash(path):
  try:
    hasher = hashlib.sha256()
    input_file = open(path, "rb")

    while True:
      buffer = input_file.read(1048576)
      if not buffer:
        break

      hasher.update(buffer)

    return hasher.hexdigest()

  except:
    return None
if __name__ == "__main__":
  exit_code = main(len(sys.argv), sys.argv)
  exit(exit_code)

