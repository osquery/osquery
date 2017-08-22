require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rapidjson < AbstractOsqueryFormula
  desc "JSON parser/generator for C++ with SAX and DOM style APIs"
  homepage "https://miloyip.github.io/rapidjson/"
  url "https://github.com/miloyip/rapidjson/archive/v1.1.0.tar.gz"
  sha256 "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e"
  head "https://github.com/miloyip/rapidjson.git"

  bottle do
    cellar :any_skip_relocation
    sha256 "8725e7b2e737904b7d72cfd9d844341310e42221d8c9c7df96d8380414bfc503" => :sierra
    sha256 "928f6189837de2419d4936340e9b29394454fb2ec65b1deac2923fb2155ad584" => :x86_64_linux
  end

  option "without-docs", "Don't build documentation"

  depends_on "cmake" => :build
  depends_on "doxygen" => :build if build.with? "docs"

  def install
    args = std_cmake_args
    args << "-DRAPIDJSON_BUILD_DOC=OFF" if build.without? "docs"
    system "cmake", ".", *args
    system "make", "install"
  end

  test do
    system ENV.cxx, "#{share}/doc/RapidJSON/examples/capitalize/capitalize.cpp", "-o", "capitalize"
    assert_equal '{"A":"B"}', pipe_output("./capitalize", '{"a":"b"}')
  end
end
