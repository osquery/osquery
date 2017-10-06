require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Yara < AbstractOsqueryFormula
  desc "Malware identification and classification tool"
  homepage "https://github.com/VirusTotal/yara/"
  head "https://github.com/VirusTotal/yara.git"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "645665d4b083262f89895e2ba17702e40e5022dfcad2ef6b7599962a6232aaea" => :sierra
    sha256 "dfab5e0b5061d3075a0d20ac7a9455196da4606233e8dca89206b8a23af15e64" => :x86_64_linux
  end

  stable do
    url "https://github.com/VirusTotal/yara/archive/v3.5.0.tar.gz"
    sha256 "4bc72ee755db85747f7e856afb0e817b788a280ab5e73dee42f159171a9b5299"

    patch do
      # Fixes variable redefinitions.
      url "https://github.com/VirusTotal/yara/commit/a0bb3836f16e3c5d0c2a1da097a1ebacbebc3a94.patch"
      sha256 "dd21219d8137bc8167c7051ea0346119843f4e37c84b1a3b96418fa7e8e62179"
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
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end
end
