require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Cppcheck < AbstractOsqueryFormula
  desc "Static analysis of C and C++ code"
  homepage "https://sourceforge.net/projects/cppcheck/"
  url "https://github.com/danmar/cppcheck/archive/1.75.tar.gz"
  sha256 "d3732dba3fb4dee075009e2422cd9b48bbd095249994ec60550aee43026030e5"
  head "https://github.com/danmar/cppcheck.git"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "f2a840d08824c49920678b68dd80b90e8b2fb542cc798c546600aa7e4997b018" => :sierra
    sha256 "c90661a8669334718bab86d6768933dfed61c1d3f5c1c0fc16bfd679ac6dd7c3" => :x86_64_linux
  end

  option "without-rules", "Build without rules (no pcre dependency)"

  depends_on "pcre" if build.with? "rules"

  def install
    # Man pages aren't installed as they require docbook schemas.
    args = []
    args << "-DHAVE_RULES=ON" if build.with? "rules"

    rm_rf "build"
    mkdir "build" do
      args += osquery_cmake_args
      system "cmake", "..", *args
      system "make"
      system "make", "install"
    end
  end
end
