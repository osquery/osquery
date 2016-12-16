require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Thrift < AbstractOsqueryFormula
  desc "Framework for scalable cross-language services development"
  homepage "https://thrift.apache.org/"
  url "https://www.apache.org/dyn/closer.cgi?path=/thrift/0.9.3/thrift-0.9.3.tar.gz"
  sha256 "b0740a070ac09adde04d43e852ce4c320564a292f26521c46b78e0641564969e"
  revision 3

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "53780643a25a2d09098159f33415d274f43e6ef0f46ea7bcc64ca698dd180cd9" => :sierra
    sha256 "f662c63b728d14c175103561e12681e5589a587140312e3ce641661ac6821e3d" => :x86_64_linux
  end

  depends_on "bison" => :build
  depends_on "openssl"
  depends_on :python => :optional

  # Remove SSLv3
  # See https://github.com/apache/thrift/commit/b819260c653f6fd9602419ee2541060ecb930c4c
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
      "--with-cpp",
      "--with-python",
      "--with-openssl=#{HOMEBREW_PREFIX}"
    ]

    ENV.prepend_path "PATH", Formula["bison"].bin
    system "./bootstrap.sh" unless build.stable?
    system "./configure", "--disable-debug",
                          "--prefix=#{prefix}",
                          "--libdir=#{lib}",
                          *exclusions
    system "make", "-j#{ENV.make_jobs}"
    system "make", "install"
  end
end

__END__
diff --git a/lib/cpp/src/thrift/transport/TSSLSocket.cpp b/lib/cpp/src/thrift/transport/TSSLSocket.cpp
index 98c5326..7c73f4e 100644
--- a/lib/cpp/src/thrift/transport/TSSLSocket.cpp
+++ b/lib/cpp/src/thrift/transport/TSSLSocket.cpp
@@ -139,8 +139,10 @@ static char uppercase(char c);
 SSLContext::SSLContext(const SSLProtocol& protocol) {
   if (protocol == SSLTLS) {
     ctx_ = SSL_CTX_new(SSLv23_method());
+#ifndef OPENSSL_NO_SSL3
   } else if (protocol == SSLv3) {
     ctx_ = SSL_CTX_new(SSLv3_method());
+#endif
   } else if (protocol == TLSv1_0) {
     ctx_ = SSL_CTX_new(TLSv1_method());
   } else if (protocol == TLSv1_1) {
diff --git a/lib/cpp/src/thrift/transport/TServerSocket.cpp b/lib/cpp/src/thrift/transport/TServerSocket.cpp
index daa1524..c1e6676 100644
--- a/lib/cpp/src/thrift/transport/TServerSocket.cpp
+++ b/lib/cpp/src/thrift/transport/TServerSocket.cpp
@@ -528,6 +528,12 @@ shared_ptr<TTransport> TServerSocket::acceptImpl() {
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
