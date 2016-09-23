require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Asio < AbstractOsqueryFormula
  desc "Cross-platform C++ Library for asynchronous programming"
  homepage "https://think-async.com/Asio"
  url "https://github.com/chriskohlhoff/asio/archive/asio-1-10-8.tar.gz"
  sha256 "fc475c6b737ad92b944babdc3e5dcf5837b663f54ba64055dc3d8fc4a3061372"
  head "https://github.com/chriskohlhoff/asio.git"
  version "1.10.8"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "af9384c96b39a9589d8c3e9730fcdb7a6e496f10526ad63bb1f1e0a2b175610a" => :el_capitan
    sha256 "e3f0a2e933ec5dd787510f38215c33e92254b9cde1196d34348740618a3720d7" => :x86_64_linux
  end

  needs :cxx11

  depends_on "autoconf" => :build
  depends_on "automake" => :build

  depends_on "openssl"

  def install
    ENV.cxx11
    ENV.append "CPPFLAGS", "-DOPENSSL_NO_SSL3"

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
