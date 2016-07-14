# Trivial osquery logger tool

This script listens on specified port for requests from osquery instance(s),
logs data received to the console
and answers with valid replies (`{"node_invalid": false}` and other fields
depending on the request).

## How to start
1. Make sure you have dependencies installed (or use `pip install -r requirements.txt`):
   1. Python 3.x
   2. Flask 0.11 or newer
   3. PyYAML
2. Go to the directory `tools/logger` in the repo (where this readme is)
3. Start `./run.sh -p 1234` (substitute your desired port number).
   Other options can be determined with `./run.sh --help`.
4. Create a file named `config.yml` with data for `/config` endpoint
5. Create a file named `tasks.yml` with data for `/distributed/read` endpoint.
   These files can contain plain JSON or equivalent YAML data.
   This is to make it easier to edit them.
   For data format and recognized fields, take a look in source code comments.
