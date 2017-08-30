require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class CppNetlib < AbstractOsqueryFormula
  desc "C++ libraries for high level network programming"
  homepage "http://cpp-netlib.org"
  url "https://github.com/cpp-netlib/cpp-netlib/archive/cpp-netlib-0.12.0-final.tar.gz"
  version "0.12.0"
  sha256 "d66e264240bf607d51b8d0e743a1fa9d592d96183d27e2abdaf68b0a87e64560"
  revision 102

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "e31a4a6c1203918eeefaca7c7fc1cd66a4563ab4527dc594a3b70f8df656fd79" => :sierra
    sha256 "852481adfc61d2a5bb2e5c3e7076882c9432231c7c17dff7d57e55a9e0968cc1" => :x86_64_linux
  end

  patch :DATA

  depends_on "cmake" => :build
  depends_on "openssl"

  needs :cxx11

  def install
    ENV.cxx11
    ENV.append "CPPFLAGS", "-Wno-deprecated-declarations" if OS.mac?

    args = [
      "-DCPP-NETLIB_BUILD_TESTS=OFF",
      "-DCPP-NETLIB_BUILD_EXAMPLES=OFF",
    ]

    # NB: Do not build examples or tests as they require submodules.
    args += osquery_cmake_args
    system "cmake", *args
    system "make"
    system "make", "install"

    # Move lib64/* to lib/ on Linuxbrew
    lib64 = Pathname.new "#{lib}64"
    if lib64.directory?
      mkdir_p lib
      system "mv #{lib64}/* #{lib}/"
      rmdir lib64
    end
  end
end

__END__
diff --git a/boost/network/protocol/http/client/connection/ssl_delegate.ipp b/boost/network/protocol/http/client/connection/ssl_delegate.ipp
index b303a24..cb9c2cf 100644
--- a/boost/network/protocol/http/client/connection/ssl_delegate.ipp
+++ b/boost/network/protocol/http/client/connection/ssl_delegate.ipp
@@ -64,7 +64,10 @@ void boost::network::http::impl::ssl_delegate::connect(
     context_->use_private_key_file(*private_key_file_, asio::ssl::context::pem);

   tcp_socket_.reset(new asio::ip::tcp::socket(
-      service_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), source_port)));
+      service_, asio::ip::tcp::endpoint(endpoint.address().is_v4()
+                                            ? asio::ip::tcp::v4()
+                                            : asio::ip::tcp::v6(),
+                                        source_port)));
   socket_.reset(new asio::ssl::stream<asio::ip::tcp::socket &>(
       *(tcp_socket_.get()), *context_));
