# Trivial osquery logger tool

This script listens on specified port for requests from osquery instance(s),
logs data received to the console
and answers with valid replies (`{"node_invalid": false}` and other fields
depending on the request).

## How to start
1. Make sure you have `Python 3.x` installed
2. Make sure you have installed python package `Flask 0.11` or newer
3. Go to the directory `tools/logger` in the repo (where this readme is)
4. Start `./run.sh -p 1234` (substitute your desired port number).
   Other options can be determined with `./run.sh --help`.
