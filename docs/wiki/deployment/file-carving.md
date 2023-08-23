# File Carving with osquery

Osquery has the capability to pull files from endpoints that it is monitoring with file carving.

Simply query the `carves` table with your desired filepath and `carve=1`, which tells osquery that you want to start this carve.

```sql
SELECT * FROM carves WHERE path LIKE '/tmp/files/%%' AND carve=1;
```

The carving will happen once the scheduler dispatches the request. You can check on the `status` of a carve to see if it's completed yet. The status will be one of [STARTING, PENDING, SUCCESS, or FAILED](https://www.osquery.io/schema/current/#carves).

## How to enable file carving

File carving is disabled by default. In order to enable it, you must pass the flag `--disable_carver=false`.

Additionally you may want to configure the following flags for your backend.
```
--carver_compression=true
--carver_block_size=300000
--carver_start_endpoint=/start_uploads
--carver_continue_endpoint=/upload_blocks
--carver_disable_function=false
```
Excerpted from [this blog post](https://www.metalliccode.com/carving):

- `carver_compression` turns on Zstd compression for the files being returned
- `carver_disable_function` allows for using carve as a function