require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Sleuthkit < AbstractOsqueryFormula
  desc "Forensic toolkit"
  homepage "http://www.sleuthkit.org/"
  license "CPL-1.0 and IPL-1.0 and GPL-2.0+"
  url "https://github.com/sleuthkit/sleuthkit/archive/sleuthkit-4.6.1.tar.gz"
  sha256 "bb2c936dbc88820fc4a875bc9b610f56c6a4a61b7bc8625f86be2549a948a7a9"
  head "https://github.com/sleuthkit/sleuthkit.git"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "1d470938ab2419aee95c2e70f3f7330cdd73cd7bea8932590c97141a2ebffeaa" => :sierra
    sha256 "33c7ebfc8d049f2808045d56879e506b6bc6e22fe306cf544f6fef8adb1aec74" => :x86_64_linux
  end

  def install
    system "./bootstrap"
    system "./configure", *osquery_autoconf_flags,
                          "--disable-java"
    system "make"
    system "make", "install"
  end
end
