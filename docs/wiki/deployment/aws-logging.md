As of version 1.7.4, osquery can log results directly to Amazon AWS [Kinesis Streams](https://aws.amazon.com/kinesis/streams/) and [Kinesis Firehose](https://aws.amazon.com/kinesis/firehose/). For users of these services, `osqueryd` can eliminate the need for a separate log forwarding daemon running in your deployments.

## Configuration

The Kinesis Streams and Kinesis Firehose logger plugins are named `aws_kinesis` and `aws_firehose` respectively. They can be enabled as with other logger plugins using the config flag `logger_plugin`.

Some configuration is shared between the two plugins:

```
--aws_access_key_id VALUE               AWS access key ID override
--aws_profile_name VALUE                AWS config profile to use for auth and region config
--aws_region VALUE                      AWS region override
--aws_secret_access_key VALUE           AWS secret access key override
```

When working with AWS, osquery will look for credentials and region configuration in the following order:

1. Configuration flags
2. Profile from the [AWS config files](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files) (only if `--aws_profile_name` is specified)
3. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
4. `default` profile in the AWS config files
5. Profile from the EC2 Instance Metadata Service

### Kinesis Streams

When logging to Kinesis Streams, the stream name must be specified with `aws_kinesis_stream`, and the log flushing period can be configured with `aws_kinesis_period`.

Configuration flags for kinesis logger:

````
--aws_kinesis_random_partition_id VALUE         Use random partition keys when sending data to kinesis. Using random values will load balance over stream shards if you are using multiple shards in a stream.  Default is "false".
````

### Kinesis Firehose

Similarly for Kinesis Firehose delivery streams, the stream name must be specified with `aws_firehose_stream`, and the period can be configued with `aws_firehose_period`.

### Sample Config File
```
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10,
    "logger_plugin": "aws_kinesis,aws_firehose",
    "aws_kinesis_stream": "foo_stream",
    "aws_firehose_stream": "bar_delivery_stream",
    "aws_access_key_id": "ACCESS_KEY",
    "aws_secret_access_key": "SECRET_KEY",
    "aws_region": "us-east-1"
  },
  "schedule": {
    "time": {
      "query": "SELECT * FROM time;",
      "interval": 2,
      "removed": false
    }
  }
}
```

**Note**: Kinesis services have a maximum 1MB record size. Result logs bigger than this will not be forwarded by `osqueryd` as they will be rejected by the Kinesis services.
