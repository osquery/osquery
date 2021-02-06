# We provide this Vagrantfile as a convenience. It is not officially
# supported.  If adding boxes, please limit sources to well-known
# organizations, not individual authors.

targets = {
  "debian7" => {
    "box" => "bento/debian-7"
  },
  "debian8" => {
    "box" => "bento/debian-8"
  },
  "debian9" => {
    "box" => "bento/debian-9"
  },
  "centos6" => {
    "box" => "elastic/centos-6-x86_64"
  },
  "centos7" => {
    "box" => "elastic/centos-7-x86_64"
  },
  "ubuntu15.04" => {
    "box" => "bento/ubuntu-15.04"
  },
  "ubuntu15.10" => {
    "box" => "bento/ubuntu-15.10"
  },
  "ubuntu16.04" => {
    "box" => "bento/ubuntu-16.04"
  },
  "ubuntu16.10" => {
    "box" => "bento/ubuntu-16.10"
  },
  "ubuntu17.04" => {
    "box" => "bento/ubuntu-17.04"
  },
  "ubuntu18.04" => {
    "box" => "ubuntu/bionic64"
  },
  "ubuntu12" => {
    "box" => "ubuntu/precise64"
  },
  "ubuntu14" => {
    "box" => "ubuntu/trusty64"
  },
  "ubuntu16" => {
    "box" => "ubuntu/xenial64"
  },
  "freebsd10" => {
    "box" => "bento/freebsd-10"
  },
  "freebsd11" => {
    "box" => "bento/freebsd-11"
  },
  "archlinux" => {
    "box" => "archlinux/archlinux"
  },
  "fedora33" => {
    "box" => "fedora/33-cloud-base"
  },
  "suse11" => {
    "box" => "elastic/sles-11-x86_64"
  },
  "suse12" => {
    "box" => "elastic/sles-12-x86_64"
  },
  "aws-amazon2015.03" => {
    "box" => "osquery/aws-dummy",
    "regions" => {
      "us-east-1" => "ami-1ecae776",
      "us-west-1" => "ami-d114f295",
      "us-west-2" => "ami-e7527ed7"
    },
    "username" => "ec2-user"
  },
  "aws-rhel7.1" => {
    "box" => "osquery/aws-dummy",
    "regions" => {
      "us-east-1" => "ami-12663b7a",
      "us-west-1" => "ami-a540a5e1",
      "us-west-2" => "ami-4dbf9e7d"
    },
    "username" => "ec2-user"
  },
  "aws-rhel6.5" => {
    "box" => "osquery/aws-dummy",
    "regions" => {
      "us-east-1" => "ami-1643ff7e",
      "us-west-1" => "ami-2b171d6e",
      "us-west-2" => "ami-7df0bd4d"
    },
    "username" => "ec2-user"
  },
  "aws-ubuntu10" => {
    "box" => "osquery/aws-dummy",
    "regions" => {
      "us-east-1" => "ami-1e6f6176",
      "us-west-1" => "ami-250fe361",
      "us-west-2" => "ami-1b2a1c2b"
    },
    "username" => "ubuntu"
  },
  "aws-oracle6.6" => {
    "box" => "osquery/aws-dummy",
    "regions" => {
      "us-east-1" => "ami-20e4b748",
      "us-west-1" => "ami-f3d83db7",
      "us-west-2" => "ami-b34f6e83"
    },
    "username" => "ec2-user"
  },
  "aws-oracle5.11" => {
    "box" => "osquery/aws-dummy",
    "regions" => {
      "us-east-1" => "ami-0ecd7766",
      "us-west-1" => "ami-4b00150e",
      "us-west-2" => "ami-6b57185b"
    },
    "username" => "root"
  },
}

Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    if ENV['OSQUERY_BUILD_CPUS']
      v.cpus = ENV['OSQUERY_BUILD_CPUS'].to_i
    else
      v.cpus = 2
    end
    if ENV['OSQUERY_BUILD_MEMORY']
      v.memory = ENV['OSQUERY_BUILD_MEMORY'].to_i
    else
      v.memory = 4096
    end
  end
  config.vm.provider "vmware_desktop" do |v|
    if ENV['OSQUERY_BUILD_CPUS']
      v.cpus = ENV['OSQUERY_BUILD_CPUS'].to_i
    else
      v.cpus = 2
    end
    if ENV['OSQUERY_BUILD_MEMORY']
      v.memory = ENV['OSQUERY_BUILD_MEMORY'].to_i
    else
      v.memory = 4096
    end
  end
  config.vm.provider :aws do |aws, override|
    # Required. Credentials for AWS API.
    aws.access_key_id = ENV['AWS_ACCESS_KEY_ID']
    aws.secret_access_key = ENV['AWS_SECRET_ACCESS_KEY']
    # Name of AWS keypair for launching and accessing the EC2 instance.
    if [ ENV['AWS_KEYPAIR_NAME'] ]
      aws.keypair_name = ENV['AWS_KEYPAIR_NAME']
    end
    override.ssh.private_key_path = ENV['AWS_SSH_PRIVATE_KEY_PATH']
    # Name of AWS security group that allows TCP/22 from vagrant host.
    if [ ENV['AWS_SECURITY_GROUP'] ]
       aws.security_groups = [ ENV['AWS_SECURITY_GROUP'] ]
    end
    # Set this to the AWS region for EC2 instances.
    if ENV['AWS_DEFAULT_REGION']
      aws.region = ENV['AWS_DEFAULT_REGION']
    else
      aws.region = "us-east-1"
    end
    # Set this to the desired AWS instance type.
    if ENV['AWS_INSTANCE_TYPE']
      aws.instance_type = ENV['AWS_INSTANCE_TYPE']
    else
      aws.instance_type = "m3.large"
    end
    targets["active_region"] = aws.region
    # If using a VPC, optionally set a SUBNET_ID.
    if ENV['AWS_SUBNET_ID']
      aws.subnet_id = ENV['AWS_SUBNET_ID']
    end
  end

  targets.each do |name, target|
    box = target["box"]
    config.vm.define name do |build|
      build.vm.box = box
      if name.start_with?('aws-')
        build.vm.provider :aws do |aws, override|
          if aws.subnet_id != Vagrant::Plugin::V2::Config::UNSET_VALUE
            aws.associate_public_ip = true
          end
          aws.ami = target['regions'][targets["active_region"]]
          aws.user_data = [
            "#!/bin/bash",
            "echo 'Defaults:" + target['username'] +
              " !requiretty' > /etc/sudoers.d/999-vagrant-cloud-init-requiretty",
              "chmod 440 /etc/sudoers.d/999-vagrant-cloud-init-requiretty"
          ].join("\n")
          override.ssh.username = target['username']
          aws.tags = { 'Name' => 'osquery-vagrant-' + name }
        end
        build.vm.synced_folder ".", "/vagrant", type: "rsync",
          rsync__exclude: [
            "build",
            ".git/objects",
          ]
      end

      if name.start_with?('macos')
        config.vm.provision "shell",
          inline: "dseditgroup -o read vagrant || dseditgroup -o create vagrant"
        build.vm.synced_folder ".", "/vagrant", group: "staff", type: "rsync",
          rsync__exclude: [
            "build",
            ".git/objects",
          ]
      end

      if name.start_with?('freebsd')
        # configure the NICs
        build.vm.provider :virtualbox do |vb|
          vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
          vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
        end
        # Private network for NFS
        build.vm.network :private_network,
          ip: "192.168.56.101", :mac => "5CA1AB1E0001"
        build.vm.synced_folder ".", "/vagrant", type: "rsync",
          rsync__exclude: [
            "build",
            ".git/objects",
          ]
        build.vm.provision 'shell',
          inline:
            # Switching to latest may cause failures if dependencies are not built.
            "sudo sed -i '' -e 's/quarterly/latest/g' /etc/pkg/FreeBSD.conf;"\
            "su -m root -c 'hostname vagrant';"\
            "su -m root -c 'pkg update -f';"\
            "sudo pkg install -y openjdk8 bash git gmake python ruby;"\
            "sudo mount -t fdescfs fdesc /dev/fd;"\
            "sudo mount -t procfs proc /proc;"\
            "echo -e \""\
              "fdesc   /dev/fd     fdescfs     rw  0   0\n"\
              "proc    /proc       procfs      rw  0   0"\
            "\" | sudo tee /etc/fstab;"\
            "sudo ln -f `which bash` /bin"
      end
      if name.start_with?('ubuntu', 'debian')
        build.vm.provision 'bootstrap', type: 'shell' do |s|
          s.inline = 'sudo apt-get update;'\
                     'sudo apt-get install --yes git make python;'
        end
      end
    end
  end
end
