require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Cppcheck < AbstractOsqueryFormula
  desc "Static analysis of C and C++ code"
  homepage "https://sourceforge.net/projects/cppcheck/"
  url "https://github.com/danmar/cppcheck/archive/1.75.tar.gz"
  sha256 "d3732dba3fb4dee075009e2422cd9b48bbd095249994ec60550aee43026030e5"
  head "https://github.com/danmar/cppcheck.git"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9d05ec931b6b3e449cce066d6205205057875760396eccff8441534cd58c1b43" => :sierra
    sha256 "9499986e0e2859a8d6356a406cdff0b88a2c8c0eac3b2d3c936a7dbcbf567454" => :el_capitan
    sha256 "0001d1022bea7c04a34301ddc0d65e84045056db187df2b992306d2e62595543" => :x86_64_linux
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
