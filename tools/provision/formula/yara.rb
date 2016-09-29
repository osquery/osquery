require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Yara < AbstractOsqueryFormula
  desc "Malware identification and classification tool"
  homepage "https://github.com/VirusTotal/yara/"
  head "https://github.com/VirusTotal/yara.git"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "e9fe2b5ec31076d218d22e7190a9b010d0de8dd12330785395e8d5deeea85ea7" => :el_capitan
    sha256 "12428e1c14b244f812bb6577b993c306ff56d62e966acd0152a2b805724f9bd9" => :x86_64_linux
  end

  stable do
    url "https://github.com/VirusTotal/yara/archive/v3.5.0.tar.gz"
    sha256 "4bc72ee755db85747f7e856afb0e817b788a280ab5e73dee42f159171a9b5299"

    patch do
      url "https://github.com/VirusTotal/yara/pull/529.diff"
      sha256 "c462efecbd2be2f582d64fd0cd493cb9ccc22ea42339b508488ddb20d63c4061"
    end
  end

  depends_on "libtool" => :build
  depends_on "autoconf" => :build
  depends_on "automake" => :build

  depends_on "pcre"
  depends_on "openssl"

  def install
    ENV.cxx11

    # Use of "inline" requires gnu89 semantics
    ENV.append "CFLAGS", "-std=gnu89" if ENV.compiler == :clang

    # find Homebrew's libpcre
    ENV.append "LDFLAGS", "-L#{Formula["pcre"].opt_lib} -lpcre"

    system "./bootstrap.sh"
    system "./configure", "--disable-silent-rules",
                          "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end
end
