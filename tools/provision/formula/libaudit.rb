require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libaudit < AbstractOsqueryFormula
  desc "Linux auditing framework"
  url "https://github.com/Distrotech/libaudit/archive/audit-2.4.2.tar.gz"
  sha256 "63020c88b0f37a93438894e67e63ccede23d658277ecc6afb9d40e4043147d3f"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "60bf54676eb07529a2eaa326ef032c62c590437419b3551514b9501832ce9635" => :x86_64_linux
  end

  def install
    system "./autogen.sh"
    system "./configure", "--prefix=#{prefix}"
    cd "lib" do
      system "make"
      system "make", "install"
    end
  end
end
