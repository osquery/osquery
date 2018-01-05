require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rapidjson < AbstractOsqueryFormula
  desc "JSON parser/generator for C++ with SAX and DOM style APIs"
  homepage "https://miloyip.github.io/rapidjson/"
  license "MIT and JSON"
  url "https://github.com/miloyip/rapidjson/archive/v1.1.0.tar.gz"
  sha256 "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e"
  head "https://github.com/miloyip/rapidjson.git"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "ae50c6edc2c58f2d640a44f8e7a28134745385c938485e00999d7c1b3341fa68" => :sierra
    sha256 "7c6a3834c92fe9474a59db72c09cbe0c505d82b584d4aacbfa00ab8a983a5142" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    # Needed with LLVM 5.0.1
    append "CXXFLAGS", "-Wno-zero-as-null-pointer-constant -Wno-shadow" if OS.linux?

    args = std_cmake_args
    args << "-DRAPIDJSON_BUILD_DOC=OFF"
    system "cmake", ".", *args
    system "make", "install"
  end
end
