require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Asio < AbstractOsqueryFormula
  desc "Cross-platform C++ Library for asynchronous programming"
  homepage "https://think-async.com/Asio"
  url "https://github.com/chriskohlhoff/asio/archive/asio-1-10-8.tar.gz"
  sha256 "fc475c6b737ad92b944babdc3e5dcf5837b663f54ba64055dc3d8fc4a3061372"
  head "https://github.com/chriskohlhoff/asio.git"
  version "1.10.8"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "cadcd03c335aa18e34f23cd7b0359c3086a048eb23abe3fc0ebbafc159764317" => :sierra
    sha256 "eca07734acb0c03f8c717fe69e0eaf4e41b0f18be36e6300c2a0d7a73e78f6dd" => :x86_64_linux
  end

  needs :cxx11

  depends_on "autoconf" => :build
  depends_on "automake" => :build

  depends_on "openssl"

  def install
    ENV.cxx11
    ENV.append "CPPFLAGS", "-DOPENSSL_NO_SSL3"
    ENV.append "CPPFLAGS", "-Wno-deprecated-declarations" if OS.mac?

    args = %W[
      --disable-dependency-tracking
      --disable-silent-rules
      --prefix=#{prefix}
    ]
    args << "--enable-boost-coroutine" if build.with? "boost-coroutine"

    cd "asio"
    system "./autogen.sh"
    system "./configure", *args
    system "make", "install"
  end
end
