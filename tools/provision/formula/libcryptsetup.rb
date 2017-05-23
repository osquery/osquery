require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libcryptsetup < AbstractOsqueryFormula
  desc "Open source disk encryption libraries"
  homepage "https://gitlab.com/cryptsetup/cryptsetup"
  url "https://osquery-packages.s3.amazonaws.com/deps/cryptsetup-1.6.7.tar.gz"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "5acc82258d7ca40af7d822e03e561a57880879d15b8d8e9887213873206e5455" => :x86_64_linux
  end

  def install
    args = [
      "--disable-selinux",
      "--disable-udev",
      "--disable-veritysetup",
      "--disable-nls",
      "--disable-kernel_crypto",
      "--enable-static",
      "--disable-shared",
    ]

    system "./autogen.sh", "--prefix=#{prefix}", *args
    cd "lib" do
      system "make"
      system "make", "install"
    end
  end
end
