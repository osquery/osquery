require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libsmartctl < AbstractOsqueryFormula
  desc "SMART hard drive monitoring; Fork with smartctl exposed as a static library"
  homepage "https://www.smartmontools.org/"
  url "https://github.com/allanliu/smartmontools/archive/v0.3.1.tar.gz"
  sha256 "a7bde3039f207a88bee72ae7c89bc4442dc65fbe76fc1a9974718d1a128a1c0b"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b637aa562d4dc247276f0d9122c90e65c49498ae2f51d07fb5e417149c073d13" => :sierra
    sha256 "4f46f17db5c3ff7600916f680f89ebf0f21c30772df397c4e9ac23ada234456d" => :x86_64_linux
  end

  def install
    inreplace "autogen.sh", "1.15 1.14", "1.16 1.15 1.14"

    system "./autogen.sh"

    ENV.append "CXXFLAGS", "-fPIC -s -Os"
    system "./configure", *osquery_autoconf_flags
    system "make", "install"
  end
end
