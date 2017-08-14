require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libcryptsetup < AbstractOsqueryFormula
  desc "Open source disk encryption libraries"
  homepage "https://gitlab.com/cryptsetup/cryptsetup"
  url "https://osquery-packages.s3.amazonaws.com/deps/cryptsetup-1.6.7.tar.gz"
  revision 102

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "78810ebd7cf24de3bc17cae28efbafe72fe1f2c6370a68b027e506c1e93805d8" => :x86_64_linux
  end

  def install
    ENV.append "LDFLAGS", "-lm"

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
