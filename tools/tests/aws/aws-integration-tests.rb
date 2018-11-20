require 'ostruct'
require 'json'
require 'optparse'

# Usage:
#
# $ ruby tools/tests/aws/aws-integration-tests.rb -s osquery-kinesis-stream -r "arn:aws:iam::123456789012:role/osquery-kinesis-streams"
# -------------------------------------
# Running 'local_user_creds'
# :SUCCESS
# -------------------------------------
# Running 'osquery_assume_role'
# :SUCCESS
# -------------------------------------
# Running 'provided_session_token'
# :SUCCESS
# -------------------------------------
# :SKIPPING endpoint_override_provided_session (no local proxy)
# -------------------------------------
# :SKIPPING endpoint_override (no local proxy)
# -------------------------------------
# Running 'fail_user_creds_invalid'
# :SUCCESS
# -------------------------------------
# Running 'fail_invalid_sts_role'
# :SUCCESS


TEST_NAMES=[
  'local_user_creds',
  'osquery_assume_role',
  'provided_session_token',
  'fail_user_creds_invalid',
  'fail_invalid_sts_role',
  'endpoint_override',
  'endpoint_override_provided_session'
]

class AwsIntegrationTestRunner
  attr_reader :options, :creds, :have_local_proxy
  def initialize(options)
    @options = options
    @exe = options.test_exe_path
    @creds = get_aws_config
    check_local_proxy
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
  # In order to try the endpoint_override tests,
  # need the local reverse proxy.  See nginx-proxy in
  # https://github.com/packetzero/osquery_aws_notes
  #---------------------------------------------------------
  def check_local_proxy
    tmp = `curl --head --insecure --stderr - -o - https://localhost:443/`
    @have_local_proxy = tmp.include?("x-amzn-RequestId:")
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
  def get_config_hash()
    options = OpenStruct.new(:aws_region => @creds[:region], :aws_access_key_id => @creds[:access_key],
      :aws_secret_access_key => @creds[:secret_key], :logger_plugin => "aws_kinesis",
      :aws_session_token => "", :aws_endpoint_override => "",
      :aws_kinesis_stream => @options.kinesis_stream_name,
      :aws_kinesis_period => 1,
      :aws_kinesis_max_retry => 2,
      :disable_logging => false, :utc => true
    )
    return options
  end

  #---------------------------------------------------------
  # returns JSON string for options hashmap
  #---------------------------------------------------------
  def make_config_json(options)
    doc = { "options" => options.to_h }
    return doc.to_json
  end

  def was_successful output
    was_sent = false
    err_count = 0
    output.lines.each do |line|
      if line.start_with?("E")
        err_count += 1
      end
      if line.include?("Successfully sent") && line.include?("aws_kinesis")
        was_sent = true
      end
    end
    return was_sent && err_count == 0
  end

end

#### script execution starts here
if ARGV.count == 0
  ARGV.push "--help"
end

# defaults

platform_name = `uname -s`.strip.downcase
options = OpenStruct.new(
  :kinesis_stream_name => 'osquery-kinesis-stream',
  :role_arn => '',
  :test_exe_path => "./build/#{platform_name}/osquery/aws_logger_integration_tests",
  :test_names => TEST_NAMES,
  :verbose => false
)

# parse arguments

OptionParser.new do |opt|
  opt.on('-s VALUE','--stream STREAM_NAME','e.g. "osquery-kinesis-stream"') { |value| options.kinesis_stream_name = value }
  opt.on('-r VALUE','--role_arn ROLE_ARN_VALUE','e.g. "arn:aws:iam::123456789012:role/osquery-kinesis-streams"') { |value| options.role_arn = value }
  opt.on('-p VALUE','--path_to_exe PATH','OPTIONAL e.g. ./build/darwin/osquery/aws_logger_integration_tests') { |value| options.test_exe_path = value }
  opt.on('-v','--verbose','Write each test output and config to stdout') { |value| options.verbose = true }
  opt.on('-f VALUE','--filter TEST_LIST', "OPTIONAL Comma-delimited list of test names to run.\n\t\tFull list: #{TEST_NAMES.join(',')}") { |value| options.test_names = value.split(',') }
end.parse!

unless File.exists?(options.test_exe_path)
  puts "ERROR: Test exe not found:#{options.test_exe_path}"
  exit 2
end

osquery_configs = {}
obj = AwsIntegrationTestRunner.new(options)

# basic user creds test

cfg = obj.get_config_hash()

test_name = 'local_user_creds'
if options.test_names.include?(test_name)
  # this may or may not succeed, depending on AWS user settings
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# assume role

test_name = 'osquery_assume_role'
if options.test_names.include?(test_name)
  cfg = obj.get_config_hash()
  cfg.aws_sts_arn_role = options.role_arn
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# with role and session token

test_name = 'provided_session_token'
if options.test_names.include?(test_name)

  cfg = obj.get_config_hash()

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

# endpoint override - with provided session

test_name = 'endpoint_override_provided_session'
if options.test_names.include?(test_name)

  cfg = obj.get_config_hash()

  result = obj.assume_role options.role_arn
  if result.nil? || result[:session_token].nil?
    puts "ERROR: assume role did not provide session token"
    exit 3
  end
  cfg.aws_session_token = result[:session_token]
  cfg.aws_sts_arn_role = options.role_arn
  cfg.aws_access_key_id = result[:access_key]
  cfg.aws_secret_access_key = result[:secret_key]
  cfg.aws_endpoint_override = "localhost:443"

  # get path to local server case
  # assuming this ruby script lives in osquery/tools/tests/aws/
  cfg.tls_server_certs = "#{File.dirname(__FILE__)}/../test_server_ca.pem"
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# endpoint override

test_name = 'endpoint_override'
if options.test_names.include?(test_name)
  cfg = obj.get_config_hash()
#  cfg.aws_sts_arn_role = options.role_arn

  cfg.aws_endpoint_override = "localhost:443"
  # get path to local server case
  # assuming this ruby script lives in osquery/tools/tests/aws/
  cfg.tls_server_certs = "#{File.dirname(__FILE__)}/../test_server_ca.pem"
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# invalid secret

test_name = 'fail_user_creds_invalid'
if options.test_names.include?(test_name)
  cfg = obj.get_config_hash()
  cfg.aws_secret_access_key = 'xxxxxx'
  # this may or may not succeed, depending on AWS user settings
  osquery_configs[test_name] = obj.make_config_json(cfg)
end

# invalid role

test_name = 'fail_invalid_sts_role'
if options.test_names.include?(test_name)
  cfg = obj.get_config_hash()
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

  puts "-------------------------------------"
  if name.start_with?("endpoint_override") && !obj.have_local_proxy
    puts ":SKIPPING #{name} (no local proxy)"
    next
  end

  path="/tmp/aws_int_test.conf"

  File.open(path, "w") { |f| f.write(config_content) }
  puts "Running '#{name}'"
  STDOUT.flush

  puts "\n  Config:#{config_content}\n\n" if (options.verbose)

  output = obj.run_test path
  if obj.was_successful(output) || name.start_with?("fail")
    puts ":SUCCESS"
    puts output if options.verbose
  else
    puts ":FAILED"
    puts output
  end

  File.unlink path
end
