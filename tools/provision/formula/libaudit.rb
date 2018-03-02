require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libaudit < AbstractOsqueryFormula
  desc "Linux auditing framework"
  homepage "https://github.com/Distrotech/libaudit"
  license "LGPL-2.1+"
  url "https://github.com/Distrotech/libaudit/archive/audit-2.4.2.tar.gz"
  sha256 "63020c88b0f37a93438894e67e63ccede23d658277ecc6afb9d40e4043147d3f"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "a4f1e5f347690848cd2cf62ab10934d097c15989e23f3954033328b1d50e3334" => :x86_64_linux
  end

  def install
    system "./autogen.sh"
    system "./configure", "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    cd "lib" do
      system "make"
      system "make", "install"
    end
  end
end
