require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class FbthriftFolly < AbstractOsqueryFormula
  desc "Collection of reusable C++ library artifacts developed at Facebook"
  homepage "https://github.com/facebook/folly"
  url "https://github.com/facebook/folly/archive/v2017.12.25.00.tar.gz"
  sha256 "ac774d9250309eb4f7f6b780e2c60d82bdeeed13a9ce6b55f96734047e0b8258"
  revision 200

  depends_on "glog"
  depends_on "gflags"
  depends_on "boost"
  depends_on "xz"
  depends_on "snappy"
  depends_on "lz4"
  depends_on "openssl"

  depends_on "libevent"
  depends_on "double-conversion"

  needs :cxx11

  def install
    ENV.cxx11

    cd "folly" do
      inreplace [
        "experimental/symbolizer/Symbolizer.cpp",
        "test/ExpectedTest.cpp",
        "ExceptionWrapper.h",
      ], "#ifdef __GNUC__", "#ifndef __clang__"

      inreplace [
        "experimental/symbolizer/Makefile.am",
       ], "StackTrace.cpp", ""

       inreplace [
         "Demangle.cpp",
       ], "FOLLY_HAVE_CPLUS_DEMANGLE_V3_CALLBACK", "FOLLY_HAVE_CPLUS_DEMANGLE_V3_CALLBACK1"

      inreplace [
        "Makefile.am",
       ], "experimental/symbolizer/StackTrace.cpp", ""


      system "autoreconf", "-fvi"
      system "./configure", "--prefix=#{prefix}", "--disable-silent-rules",
                            "--disable-dependency-tracking"
      system "make"
      system "make", "install"
    end
  end
end
