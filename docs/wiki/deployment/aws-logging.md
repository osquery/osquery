# Logging osquery to AWS

As of osquery version 1.7.4, osquery can log results directly to Amazon AWS [Kinesis Streams](https://aws.amazon.com/kinesis/data-streams/) and [Kinesis Firehose](https://aws.amazon.com/kinesis/data-firehose/). For users of these services, `osqueryd` can eliminate the need for a separate log forwarding daemon running in your deployments.

## Configuration

The Kinesis Streams and Kinesis Firehose logger plugins are named `aws_kinesis` and `aws_firehose` respectively. They can be enabled as with other logger plugins using the [CLI flag](https://github.com/osquery/osquery/blob/master/docs/wiki/installation/cli-flags.md) `logger_plugin`. For this example, both logger plugins must be enabled via `--logger-plugin=aws_kinesis,aws_firehose`.

Some configuration is shared between the two plugins:

```
--aws_access_key_id VALUE               AWS access key ID override
--aws_profile_name VALUE                AWS config profile to use for auth and region config
--aws_region VALUE                      AWS region override
--aws_secret_access_key VALUE           AWS secret access key override
--aws_sts_arn_role VALUE                AWS STS assume role ARN
--aws_sts_region VALUE                  AWS STS assume role region
--aws_sts_session_name VALUE            AWS STS session name
--aws_sts_timeout VALUE                 AWS STS temporary credential timeout period in seconds (900-3600)
--aws_enable_proxy VALUE                Enable proxying of HTTP/HTTPS requests in AWS client config (true or false)
--aws_proxy_scheme VALUE                Proxy HTTP scheme for use in AWS client config (http or https)
--aws_proxy_host VALUE                  Proxy host for use in AWS client config
--aws_proxy_port VALUE                  Proxy port for use in AWS client config
--aws_proxy_username VALUE              Proxy username for use in AWS client config
--aws_proxy_password VALUE              Proxy password for use in AWS client config
```

When working with AWS, osquery will look for credentials and region configuration in the following order:

1. Configuration flags
2. Profile from the [AWS config files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) (only if `--aws_profile_name` is specified)
3. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
4. `default` profile in the AWS config files
5. Profile from the EC2 Instance Metadata Service

All of the STS configuration flags are optional. However, if `aws_sts_arn_role` is set, you can utilize temporary credentials via assume role with the [AWS Security Token Service](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

### Kinesis Streams

When logging to Kinesis Streams, the stream name must be specified with `aws_kinesis_stream`, and the log flushing period can be configured with `aws_kinesis_period`.  

Setting `aws_kinesis_random_partition_key` to `true` will use random partition keys when sending data to Kinesis. Using random values will load balance over stream shards if you are using multiple shards in a stream. Note that using this setting will result in the logs of each host distributed across shards, so do not use it if you need logs from each host to be processed by a consistent shard. The default for this setting is `false`.

Custom endpoint for non-AWS Kinesis implementations can be specified with `aws_kinesis_endpoint`.

### Kinesis Firehose

Similarly for Kinesis Firehose delivery streams, the stream name must be specified with `aws_firehose_stream`, and the period can be configured with `aws_firehose_period`.

Custom endpoint for non-AWS Firehose implementations can be specified with `aws_firehose_endpoint`.

### Sample Config File

```JSON
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10,
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
