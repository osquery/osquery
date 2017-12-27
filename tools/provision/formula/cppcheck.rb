require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Cppcheck < AbstractOsqueryFormula
  desc "Static analysis of C and C++ code"
  homepage "https://sourceforge.net/projects/cppcheck/"
  url "https://github.com/danmar/cppcheck/archive/1.75.tar.gz"
  sha256 "d3732dba3fb4dee075009e2422cd9b48bbd095249994ec60550aee43026030e5"
  head "https://github.com/danmar/cppcheck.git"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "cca248e43d8df6b6663998609036bf15ca91c5f79f19d1f45713e3668e352a44" => :sierra
    sha256 "ed4d2bde63dce396d0f46814fc9d33057c0dc18e140b7d2fb06c0ffb0b6cc9d4" => :x86_64_linux
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
