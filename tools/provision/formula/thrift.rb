require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Thrift < AbstractOsqueryFormula
  desc "Framework for scalable cross-language services development"
  homepage "https://thrift.apache.org/"
  url "https://www.apache.org/dyn/closer.cgi?path=/thrift/0.9.3/thrift-0.9.3.tar.gz"
  sha256 "b0740a070ac09adde04d43e852ce4c320564a292f26521c46b78e0641564969e"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "04f916d7a8e273a129f79b4223c754856113f6de2953cb3a6a51b206f5d5b41d" => :el_capitan
    sha256 "4931461ade98a71254a146b545d767515cfadd63f816630d17f31f0d95e0ede9" => :x86_64_linux
  end

  depends_on "bison" => :build
  depends_on "openssl"
  depends_on :python => :optional

  def install
    ENV.cxx11
    ENV["PY_PREFIX"] = prefix

    exclusions = [
      "--without-ruby",
      "--disable-tests",
      "--without-php_extension",
      "--without-haskell",
      "--without-java",
      "--without-perl",
      "--without-php",
      "--without-erlang",
      "--without-go",
      "--without-qt",
      "--without-qt4",
      "--without-node",
      "--with-cpp",
      "--with-python",
      "--with-openssl=#{Formula["openssl"]}"
    ]

    system "./bootstrap.sh" unless build.stable?
    system "./configure", "--disable-debug",
                          "--prefix=#{prefix}",
                          "--libdir=#{lib}",
                          *exclusions
    system "make", "-j#{ENV.make_jobs}"
    system "make", "install"
  end
end
