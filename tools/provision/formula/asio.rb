require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Asio < AbstractOsqueryFormula
  desc "Cross-platform C++ Library for asynchronous programming"
  homepage "https://think-async.com/Asio"
  url "https://github.com/chriskohlhoff/asio/archive/asio-1-10-8.tar.gz"
  sha256 "fc475c6b737ad92b944babdc3e5dcf5837b663f54ba64055dc3d8fc4a3061372"
  head "https://github.com/chriskohlhoff/asio.git"
  version "1.10.8"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "42d8a4f8c368cee3da90b9e0e0fca6e80833f2805e7aa208f8702a559b53323c" => :sierra
    sha256 "05cb875e46c9b6be1d08597545ae57be181b3053207ef68dd4346fd460e670e7" => :x86_64_linux
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
