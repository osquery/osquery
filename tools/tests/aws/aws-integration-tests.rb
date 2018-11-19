require 'ostruct'
require 'json'
require 'optparse'

TEST_NAMES=[
  'local_user_creds',
  'osquery_assume_role',
  'provided_session_token',
  'fail_user_creds_invalid',
  'fail_invalid_sts_role'
]

class AwsIntegrationTestRunner

  def initialize()
    @exe="./build/darwin/osquery/aws_logger_integration_tests"
  end

  #---------------------------------------------------------
  # use aws command-line to get region, access_key, secret_key
  #---------------------------------------------------------
  def get_aws_config
    cmd_path = `which aws`.strip
    unless cmd_path
      puts "ERROR: 'aws' executable is not in your path"
      exit 2
    end

    items = {}
    items[:region] = `aws configure get region`.strip
    items[:access_key] = `aws configure get aws_access_key_id`.strip
    items[:secret_key] = `aws configure get aws_secret_access_key`.strip

    unless items[:access_key]
      puts "ERROR: access_key is not configured:#{items[:access_key]}"
      exit 3
    end
    unless items[:secret_key]
      puts "ERROR: secret_key is not configured:#{items[:secret_key]}"
      exit 3
    end

    return items
  end

  #---------------------------------------------------------
  # use aws command-line to assume role, return hashmap
  # with access_key, secret_key, session_token
  #---------------------------------------------------------
  # {
  #    "Credentials": {
  #        "AccessKeyId": "ASI...K",
  #        "SecretAccessKey": "Dc...5",
  #        "SessionToken": "FJ...wU=",
  #        "Expiration": "2018-11-15T22:43:40Z"
  #    },
  #    "AssumedRoleUser": {
  #        "AssumedRoleId": "AROA3XFRBF535PLBIFPI4:osquery-test1",
  #        "Arn": "arn:aws:sts::123456789012:assumed-role/osquery-user/osquery-test1"
  #    }
  # }
  def assume_role arn

    json_response = `aws sts assume-role --role-arn "#{arn}" --role-session-name osquery-test1`
    unless $?.success?
      puts "ERROR: aws sts command-line failed"
      exit 3
    end
    doc = JSON.parse(json_response, object_class: OpenStruct) rescue nil

    #puts doc.inspect

    retval = {}
    return retval if doc.nil?

    retval[:session_token] = doc.Credentials.SessionToken rescue nil
    retval[:access_key] = doc.Credentials.AccessKeyId rescue nil
    retval[:secret_key] = doc.Credentials.SecretAccessKey rescue nil

    return retval
  end

  #---------------------------------------------------------
  # run osquery test exe with specified config
  #---------------------------------------------------------
  def run_test(config_path)
    output = `GLOG_v=1 GLOG_logtostderr=1 GLOG_stderrthreshold=1 AWS_KINESIS_TEST_CFG="#{config_path}" #{@exe} 2>&1`;
    return output
  end

  #---------------------------------------------------------
  # returns a hashmap matching names in osquery config 'options'
  #---------------------------------------------------------
  def get_config_hash(region, access_key_id="", secret_access_key="", logger_plugin="aws_kinesis")
    options = OpenStruct.new(:aws_region => region, :aws_access_key_id => access_key_id,
      :aws_secret_access_key => secret_access_key, :logger_plugin => logger_plugin,
      :aws_session_token => "", :aws_endpoint_override => "",
      :aws_kinesis_stream => "", :aws_kinesis_period => 1,
      :aws_kinesis_max_retry => 2,
      :disable_logging => false, :utc => true
    )
    return options
  end

  #---------------------------------------------------------
  # alternative signature
  #---------------------------------------------------------
  def get_config_hash2(creds, options)
    cfg = get_config_hash(creds[:region], creds[:access_key], creds[:secret_key])
    cfg.aws_kinesis_stream = options.kinesis_stream_name
    return cfg
  end

  #---------------------------------------------------------
  # returns JSON string for options hashmap
  #---------------------------------------------------------
  def make_config_json(options)
    doc = { "options" => options.to_h }
    return doc.to_json
  end

end

#### script execution starts here

# defaults

platform_name = `uname -s`.strip.downcase
options = OpenStruct.new(
  :kinesis_stream_name => 'osquery-kinesis-stream',
  :role_arn => '',
  :test_exe_path => "./build/#{platform_name}/osquery/aws_logger_integration_tests",
  :test_names => TEST_NAMES
)

# parse arguments

OptionParser.new do |opt|
  opt.on('-s VALUE','--stream STREAM_NAME','e.g. "osquery-kinesis-stream"') { |value| options.kinesis_stream_name = value }
  opt.on('-r VALUE','--role_arn ROLE_ARN_VALUE','e.g. "arn:aws:iam::123456789012:role/osquery-kinesis-streams"') { |value| options.role_arn = value }
  opt.on('-p VALUE','--path_to_exe PATH','OPTIONAL e.g. ./build/darwin/osquery/aws_logger_integration_tests') { |value| options.test_exe_path = value }
  opt.on('-f VALUE','--filter TEST_LIST', "OPTIONAL Comma-delimited list of test names to run.\n\t\tFull list: #{TEST_NAMES.join(',')}") { |value| options.test_names = value.split(',') }
end.parse!

osquery_configs = {}
obj = AwsIntegrationTestRunner.new

# get aws command-line config
creds = obj.get_aws_config

# build a hash map we can use to build JSON config

cfg = obj.get_config_hash(creds[:region], creds[:access_key], creds[:secret_key])
cfg.aws_kinesis_stream = options.kinesis_stream_name

test_name = 'local_user_creds'
if options.test_names.include?(test_name)
  # this may or may not succeed, depending on AWS user settings
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# assume role

test_name = 'osquery_assume_role'
cfg = obj.get_config_hash2(creds,options)
cfg.aws_sts_arn_role = options.role_arn
if options.test_names.include?(test_name)
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# with role and session token

test_name = 'provided_session_token'
if options.test_names.include?(test_name)

  result = obj.assume_role options.role_arn
  if result.nil? || result[:session_token].nil?
    puts "ERROR: assume role did not provide session token"
    exit 3
  end
  cfg.aws_session_token = result[:session_token]
  cfg.aws_sts_arn_role = ""
  cfg.aws_access_key_id = result[:access_key]
  cfg.aws_secret_access_key = result[:secret_key]

  osquery_configs[test_name] = obj.make_config_json(cfg)

end

# invalid secret

test_name = 'fail_user_creds_invalid'
if options.test_names.include?(test_name)
  cfg = obj.get_config_hash2(creds,options)
  cfg.aws_secret_access_key = 'xxxxxx'
  # this may or may not succeed, depending on AWS user settings
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# invalid role

test_name = 'fail_invalid_sts_role'
if options.test_names.include?(test_name)
  cfg = obj.get_config_hash2(creds,options)
  cfg.aws_sts_arn_role = "#{options.role_arn}-nosuch"
  # this may or may not succeed, depending on AWS user settings
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

if osquery_configs.empty?
  puts "ERROR: no configurations specified"
  exit 4
end

# run them

osquery_configs.each do |name, config_content|

  path="/tmp/aws_int_test.conf"

  File.open(path, "w") { |f| f.write(config_content) }
  puts "-------------------------------------"
  puts "Running '#{name}'"

  output = obj.run_test path
  puts output

  File.unlink path
end
