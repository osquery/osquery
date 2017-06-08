# Simple osquery Logger

`logger.py` is a simple osquery logger that is useful for debugging osqueryd. It listens for messages from osquery nodes, logs received data to the console, and replies with `{"node_invalid": false}`.

## Usage

1. Make sure you have the dependencies installed (or use `pip install -r requirements.txt`):
   1. Python 3.x
   2. Flask 0.11 or newer
   3. PyYAML
2. Start `./run.sh -p 1234` (substitute your desired port number).
   Other options can be determined with `./run.sh --help`.
3. Create a file named `config.yml` with data for `/config` endpoint.
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
5. Create a file named `tasks.yml` with data for the `/distributed/read` endpoint.
   Example file format:

   ```yaml
guid1: SELECT * FROM table1
guid2: SELECT * FROM table2
```
   Results of executed tasks should be returned to the `/distributed/write` endpoint.

Data files can contain plain JSON or equivalent YAML data which makes it easier to edit them.
