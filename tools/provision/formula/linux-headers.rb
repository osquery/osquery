require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LinuxHeaders < AbstractOsqueryFormula
  desc "Header files of the Linux kernel"
  homepage "https://kernel.org/"
  url "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.4.152.tar.gz"
  sha256 "5c2b498381288305d490d6da6c5b61b980b06bbb42ff5268d19c321443f5470e"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "e19f4291f8c1ef5c83d39f3a8f33b334ac83c686ff80bf71312a7b058c9c146a" => :x86_64_linux 
  end

  def install
    system "make", "headers_install", "INSTALL_HDR_PATH=#{prefix}"
    rm Dir[prefix/"**/{.install,..install.cmd}"]
  end

  test do
    assert_match "KERNEL_VERSION", File.read(include/"linux/version.h")
  end
end

