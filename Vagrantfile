targets = {
  "aws-amazon2015.03" => {
    "box" => "andytson/aws-dummy",
    "regions" => { "us-east-1" => "ami-1ecae776", "us-west-1" => "ami-d114f295" },
    "username" => "ec2-user"
  },
  "aws-rhel7.1" => {
    "box" => "andytson/aws-dummy",
    "regions" => { "us-east-1" => "ami-12663b7a", "us-west-1" => "ami-a540a5e1" },
    "username" => "ec2-user"
  },
  "aws-rhel6.6" => {
    "box" => "andytson/aws-dummy",
    "regions" => { "us-east-1" => "ami-1643ff7e", "us-west-1" => "ami-2b171d6e" },
    "username" => "ec2-user"
  },
}
Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    if ENV['OSQUERY_BUILD_CPUS']
      v.cpus = ENV['OSQUERY_BUILD_CPUS'].to_i
    else
      v.cpus = 2
    end
    v.memory = 4096
  end
  config.vm.provider :aws do |aws, override|
    # Required. Credentials for aws api. vagrant-aws will error if these are unset.
    aws.access_key_id = ENV['AWS_ACCESS_KEY_ID']
    aws.secret_access_key = ENV['AWS_SECRET_ACCESS_KEY']
    # Name of aws keypair for launching and accessing the ec2 instance.
    if [ ENV['AWS_KEYPAIR_NAME'] ]
      aws.keypair_name = ENV['AWS_KEYPAIR_NAME']
    end
    override.ssh.private_key_path = ENV['AWS_SSH_PRIVATE_KEY_PATH']
    # Name of aws security group that allows tcp/22 from vagrant host.
    if [ ENV['AWS_SECURITY_GROUP'] ]
       aws.security_groups = [ ENV['AWS_SECURITY_GROUP'] ]
    end
    # Set this to the aws region the ec2 instances should be launced in.
    if ENV['AWS_DEFAULT_REGION']
      aws.region = ENV['AWS_DEFAULT_REGION']
    else
      aws.region = "us-east-1"
    end
    # Set this to the desired aws instance type.
    if ENV['AWS_INSTANCE_TYPE']
      aws.instance_type = ENV['AWS_INSTANCE_TYPE']
    else
      aws.instance_type = "m3.large"
    end
    # hack: make aws.region accessible in targets.each do loop.
    targets["active_region"] = aws.region
  end
targets.each do |name, target|
  box = target["box"]
  config.vm.define name do |build|
    build.vm.box = box
    if name.start_with?('aws-')
      build.vm.provider :aws do |aws, override|
        aws.ami = target['regions'][targets["active_region"]]
        aws.user_data = [
          "#!/bin/bash",
          "echo 'Defaults:" + target['username'] + " !requiretty' > /etc/sudoers.d/999-vagrant-cloud-init-requiretty",
          "chmod 440 /etc/sudoers.d/999-vagrant-cloud-init-requiretty"
        ].join("\n")
        override.ssh.username = target['username']
        aws.tags = { 'Name' => name }
      end
    end
    if name == 'freebsd10'
      # configure the NICs
      build.vm.provider :virtualbox do |vb|
        vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
        vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
      end
      # Private network for NFS
      build.vm.network :private_network, ip: "192.168.56.101"
      build.vm.synced_folder ".", "/vagrant", type: "nfs"
      build.vm.provision "shell",
        inline: "pkg install -y gmake"
      end
    end
  end
end
