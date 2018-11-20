As of version 1.7.4, osquery can log results directly to Amazon AWS [Kinesis Streams](https://aws.amazon.com/kinesis/streams/) and [Kinesis Firehose](https://aws.amazon.com/kinesis/firehose/). For users of these services, `osqueryd` can eliminate the need for a separate log forwarding daemon running in your deployments.

## Configuration

The Kinesis Streams and Kinesis Firehose logger plugins are named `aws_kinesis` and `aws_firehose` respectively. They can be enabled as with other logger plugins using the config flag `logger_plugin`.

Some configuration is shared between the two plugins:

```
--aws_region VALUE                      AWS region override
--aws_access_key_id VALUE               AWS access key ID override
--aws_secret_access_key VALUE           AWS secret access key override

--aws_profile_name VALUE                AWS config profile to use for auth and region config

--aws_sts_arn_role VALUE                AWS STS assume role ARN
--aws_sts_region VALUE                  AWS STS assume role region
--aws_sts_session_name VALUE            AWS STS session name
--aws_sts_timeout VALUE                 AWS STS temporary credential timeout period in seconds (900-3600)
--aws_session_token VALUE               AWS STS token

--aws_enable_proxy VALUE                Enable proxying of HTTP/HTTPS requests in AWS client config (true or false)
--aws_proxy_scheme VALUE                Proxy HTTP scheme for use in AWS client config (http or https)
--aws_proxy_host VALUE                  Proxy host for use in AWS client config
--aws_proxy_port VALUE                  Proxy port for use in AWS client config
--aws_proxy_username VALUE              Proxy username for use in AWS client config
--aws_proxy_password VALUE              Proxy password for use in AWS client config

--aws_endpoint_override VALUE           Hostname to use instead of amazonaws.com

```

When working with AWS, osquery will look for credentials and region configuration in the following order:

1. Configuration flags
2. Profile from the [AWS config files](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files) (only if `--aws_profile_name` is specified)
3. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
4. `default` profile in the AWS config files
5. Profile from the EC2 Instance Metadata Service

## Credential Considerations

- **Never use the access keys for the root user for the AWS account.**  This would be like putting your AWS console username and password in your osquery config files.

- **How would your environment invalid data or getting spammed with logs?**  Each device running osquery will have configuration containing AWS credentials to write to your AWS Kinesis or Firehose endpoints.  What if an agent had a bug and started sending 1000 messages per minute?  What if a malicious actor takes the credentials and crafts logs that are intended to break your server-side processing?  For these reasons, we need to consider how to mitigate those problems, revoke credentials, and how to control access to them.  There are a few different ways to configure AWS credentials for osquery to help manage those situations.

- **Use tls configuration**  Consider using the TLS configuration, in which the osquery agents fetch the configuration periodically (e.g. 5 minutes) from a server.  This will help recover from changes to AWS credentials.
- **Dropped messages** The AWS Kinesis logger is configured to retry (default 100 times) before dropping a message.

## Credential Configuration Scenarios
There are a few ways to provide osquery agents with the security credentials needed to write to AWS Kinesis or Firehose endpoints.

**1. User security tokens**

This is the simplest case, in which the 'Access Keys' for a user account are used (aws_access_key_id, aws_secret_access_key). You will want to create an IAM user with just the access needed:
 - Kinesis / Firehose write access (e.g. PutRecord)
 - no console access (default for new IAM users)

You are unlikely to create IAM user accounts for each osquery endpoint device.  Therefore, if you need to revoke credentials, it will affect all osquery agents.

**2. STS Tokens for IAM Role**

In this scenario, configure the agents with Access Keys for an IAM user that has 'sts:AssumeRole' permission, along with a `aws_sts_arn_role` flag to specify a role to assume. See [AWS Security Token Service](http://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).  That role has restricted permissions to write to Kinesis or Firehose.  The osquery agent will try to assume the role and if successful will be given the new STS Access Keys, SessionToken, and Expiration Time.  When a token expires, osquery will do the assume role request again to reacquire credentials.

**3. Server provided STS Token**

In this scenario, a server provides Access Keys, along with `aws_session_token` in the configuration.  The periodic refresh of the TLS configuration provides means to update the AWS credentials as needed, with the ability to selectively deny AWS credentials to specific agents.  This is the most flexible, but also the most complicated, as it requires server management of STS tokens.

### Kinesis Streams

When logging to Kinesis Streams, the stream name must be specified with `aws_kinesis_stream`, and the log flushing period can be configured with `aws_kinesis_period` (defaults to 10 seconds).  The number of retries before dropping a log record is configured using `aws_kinesis_max_retry`, which defaults to 100.

Setting aws_kinesis_random_partition_key to true will use random partition keys when sending data to Kinesis. Using random values will load balance over stream shards if you are using multiple shards in a stream.  Note that using this setting will result in the logs of each host distributed across shards, so do not use it if you need logs from each host to be processed by a consistent shard.  The default for this setting is "false".

### Kinesis Firehose

Similarly for Kinesis Firehose delivery streams, the stream name must be specified with `aws_firehose_stream`, and the period can be configured with `aws_firehose_period`.

### Sample Config File
The following shows the configuration syntax.  Typically you will only have one AWS logger specified at a time (either firehose or kinesis).
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

**Note**: Kinesis services have a maximum 1MB record size. Result logs bigger than this will not be forwarded by **osqueryd** as they will be rejected by the Kinesis services.
