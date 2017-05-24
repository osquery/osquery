require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Thrift < AbstractOsqueryFormula
  desc "Framework for scalable cross-language services development"
  homepage "https://thrift.apache.org/"
  url "http://www-us.apache.org/dist/thrift/0.10.0/thrift-0.10.0.tar.gz"
  sha256 "2289d02de6e8db04cbbabb921aeb62bfe3098c4c83f36eec6c31194301efa10b"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "f9bbba4aecd4de780e879dd71bcbd18e819ed8355e700177a543860120f4086b" => :sierra
    sha256 "e818505723a34e425cd2e35acccd992f8f79287bfa77ec7bdda4e9df4083d5e2" => :x86_64_linux
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
    system "./bootstrap.sh" unless build.stable?
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
