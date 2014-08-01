OPERATING_SYSTEMS = [
  "chef/ubuntu-14.04", # Ubuntu 14.04 LTS
  "chef/centos-6.5", # CentOS 6.5
]

Vagrant.configure("2") do |config|

  OPERATING_SYSTEMS.each do |os|

    org, os_name = os.split("/")

    config.vm.define os_name do |box|
      box.vm.box = os

      box.vm.provision "shell", path: "devtools/install_chef.sh"

      box.vm.provision "chef_solo" do |chef|
        chef.cookbooks_path = "devtools/cookbooks"
        chef.add_recipe("osquery::compile")
      end

      box.vm.provision "shell", path: "devtools/test_runner.sh"

    end

  end

end
