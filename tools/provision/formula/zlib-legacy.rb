require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class ZlibLegacy < AbstractOsqueryFormula
  desc "General-purpose lossless data-compression library"
  homepage "http://www.zlib.net/"
  url "https://github.com/madler/zlib/archive/v1.2.3.tar.gz"
  sha256 "2134178c123ea8252fd6afc9b794d9a2df480ccd030cc5db720a41883676fc2e"

  keg_only :provided_by_osx

  option :universal

  # configure script fails to detect the right compiler when "cc" is
  # clang, not gcc. zlib mantainers have been notified of the issue.
  # See: https://github.com/Homebrew/homebrew-dupes/pull/228
  patch :DATA if OS.mac?

  # http://zlib.net/zlib_how.html
  resource "test_artifact" do
    url "http://zlib.net/zpipe.c"
    version "20051211"
    sha256 "68140a82582ede938159630bca0fb13a93b4bf1cb2e85b08943c26242cf8f3a6"
  end

  set_legacy

  def install
    ENV.universal_binary if build.universal?
    system "./configure", "--prefix=#{prefix}", "--shared"
    system "make", "install"
  end

  test do
    testpath.install resource("test_artifact")
    system ENV.cc, "zpipe.c", "-I#{include}", "-L#{lib}", "-lz", "-o", "zpipe"

    touch "foo.txt"
    output = ("./zpipe < foo.txt > foo.txt.z")
    system output
    assert File.exist?("foo.txt.z")
  end
end

__END__
diff --git a/configure b/configure
index b77a8a8..54f33f7 100755
--- a/configure
+++ b/configure
@@ -159,6 +159,7 @@ case "$cc" in
 esac
 case `$cc -v 2>&1` in
   *gcc*) gcc=1 ;;
+  *clang*) gcc=1 ;;
 esac
 
 show $cc -c $test.c
