require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Cppcheck < AbstractOsqueryFormula
  desc "Static analysis of C and C++ code"
  homepage "https://sourceforge.net/projects/cppcheck/"
  url "https://github.com/danmar/cppcheck/archive/1.75.tar.gz"
  sha256 "d3732dba3fb4dee075009e2422cd9b48bbd095249994ec60550aee43026030e5"
  head "https://github.com/danmar/cppcheck.git"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b7dc822bd2b697914325e56fae1a5a6bf6d4a3ef38c678e58942f37cd7b5ec46" => :sierra
    sha256 "46fcfe80187918d6dfdcbd5dfc5fac51b94e26fe8709fdc5b623c2810911defd" => :x86_64_linux
  end

  option "without-rules", "Build without rules (no pcre dependency)"

  depends_on "pcre" if build.with? "rules"

  def install
    # Man pages aren't installed as they require docbook schemas.
    args = []
    args << "-DHAVE_RULES=ON" if build.with? "rules"

    mkdir "build" do
      args += osquery_cmake_args
      system "cmake", "..", *args
      system "make"
      system "make", "install"
    end
  end
end
