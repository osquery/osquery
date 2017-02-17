require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class CppNetlib < AbstractOsqueryFormula
  desc "C++ libraries for high level network programming"
  homepage "http://cpp-netlib.org"
  url "https://github.com/cpp-netlib/cpp-netlib/archive/cpp-netlib-0.12.0-final.tar.gz"
  version "0.12.0"
  sha256 "d66e264240bf607d51b8d0e743a1fa9d592d96183d27e2abdaf68b0a87e64560"
  revision 3

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6847b96010d47388abd54587b2142b9fca3bec1e8172eb9ebf8f6742b2103a37" => :sierra
    sha256 "e906fa8d5347a923fffe6443a8ec1346a6e798ed7bf6071b5a002958d25eca3a" => :x86_64_linux
  end

  patch do
    url "https://github.com/cpp-netlib/cpp-netlib/commit/49e21a8.diff"
    sha256 "5dcbfad8f08f11d706f4d0d644a6c2fb0ef424cc8089fd54dfe3792a0abedbea"
  end

  depends_on "cmake" => :build
  depends_on "openssl"

  needs :cxx11

  def install
    ENV.cxx11

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
