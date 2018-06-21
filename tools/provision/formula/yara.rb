require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Yara < AbstractOsqueryFormula
  desc "Malware identification and classification tool"
  homepage "https://github.com/VirusTotal/yara/"
  license "BSD-3-Clause"
  url "https://github.com/VirusTotal/yara/archive/v3.7.1.tar.gz"
  sha256 "df077a29b0fffbf4e7c575f838a440f42d09b215fcb3971e6fb6360318a64892"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6bbcc74e694c2d49d9d9f5d2dfd8383a4210ac0905a1778913a168462aa7ee43" => :sierra
    sha256 "d76fee94374de3b227e16c969a6814f0639437db86ef16f3a6fc02eea889617e" => :x86_64_linux
  end

  depends_on "pcre"
  depends_on "openssl"

  def install
    ENV.cxx11

    # Use of "inline" requires gnu89 semantics
    ENV.append "CFLAGS", "-std=gnu89"

    # find Homebrew's libpcre
    ENV.append "LDFLAGS", "-L#{Formula["osquery/osquery-local/pcre"].opt_lib} -lpcre"

    system "./bootstrap.sh"
    system "./configure", *osquery_autoconf_flags
    system "make", "install"
  end
end
