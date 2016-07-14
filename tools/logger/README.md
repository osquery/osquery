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
4. Create a file named `config.yml` with data for `/config` endpoint.
   Example file format (all keys are optional):
   ```yaml
file_paths:
  category1:  # list of paths
  - path1
  - path2
  - path3
  category2:
  - path10
schedule:
  query_name1:
    query: SELECT * FROM somewhere
    interval: 100
    platform: myplatform
    version: 1.2.3
    description: My Awesome Query
    value: some value
    removed: false
packs:
  packname:
    platform: myplatform
    version: 1.2.3
    shard: 15
    discovery:  # list of SQLs
    - SELECT * FROM table1
    - SELECT * FROM table2
    queries:  # same format as for `schedule` tag above
      queryname:
        query: SELECT * FROM somewhere
        interval: 100
        platform: myplatform
        version: 1.2.3
        description: My Awesome Query
        value: some value
        removed: false
```
5. Create a file named `tasks.yml` with data for `/distributed/read` endpoint.
   Example file format:
   ```yaml
guid1: SELECT * FROM table1
guid2: SELECT * FROM table2
```
   Results of executed tasks should be probably returned to `/distributed/write` endpoint.

Data files can contain plain JSON or equivalent YAML data;
this is to make it easier to edit them.
