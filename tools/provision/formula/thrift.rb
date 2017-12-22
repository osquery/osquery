require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Thrift < AbstractOsqueryFormula
  desc "Framework for scalable cross-language services development"
  homepage "https://thrift.apache.org/"
  license "Apache-2.0"
  url "https://github.com/apache/thrift/archive/0.11.0.tar.gz"
  sha256 "0e324569321a1b626381baabbb98000c8dd3a59697292dbcc71e67135af0fefd"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "8f7a14271460fc75e3fe44ac21dba7f3f88bd0dbf153f5b5ea20579ddeb6171a" => :sierra
    sha256 "9ab1a97df4d5fca73a8144ba9c1471a1447e0b291df85d6dc269031d97904992" => :x86_64_linux
  end

  depends_on "bison" => :build
  depends_on "openssl"

  patch :DATA

  def install
    ENV.cxx11
    ENV["PY_PREFIX"] = prefix
    ENV.append "CPPFLAGS", "-DOPENSSL_NO_SSL3"

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
      "--without-nodejs",
      "--without-python",
      "--with-cpp",
      "--with-openssl=#{Formula["osquery/osquery-local/openssl"].prefix}"
    ]

    ENV.prepend_path "PATH", Formula["bison"].bin
    system "./bootstrap.sh"
    system "./configure", "--disable-debug",
                          "--prefix=#{prefix}",
                          "--libdir=#{lib}",
                          "--disable-shared",
                          "--enable-static",
                          *exclusions
    system "make", "-j#{ENV.make_jobs}"
    system "make", "install"
  end
end

__END__
diff --git a/lib/cpp/src/thrift/transport/TServerSocket.cpp b/lib/cpp/src/thrift/transport/TServerSocket.cpp
index 87b6383..447c89d 100644
--- a/lib/cpp/src/thrift/transport/TServerSocket.cpp
+++ b/lib/cpp/src/thrift/transport/TServerSocket.cpp
@@ -584,6 +584,12 @@ shared_ptr<TTransport> TServerSocket::acceptImpl() {
         // a certain number
         continue;
       }
+
+      // Special case because we expect setuid syscalls in other threads.
+      if (THRIFT_GET_SOCKET_ERROR == EINTR) {
+        continue;
+      }
+
       int errno_copy = THRIFT_GET_SOCKET_ERROR;
       GlobalOutput.perror("TServerSocket::acceptImpl() THRIFT_POLL() ", errno_copy);
       throw TTransportException(TTransportException::UNKNOWN, "Unknown", errno_copy);
