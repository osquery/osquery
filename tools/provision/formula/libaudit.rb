require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libaudit < AbstractOsqueryFormula
  desc "Linux auditing framework"
  url "https://github.com/Distrotech/libaudit/archive/audit-2.4.2.tar.gz"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c0eca64bfd50995706b0e2321161e97d0d7161a1c9b859b3913fe49d558f5141" => :x86_64_linux
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
