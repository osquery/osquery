require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class FbthriftMstch < AbstractOsqueryFormula
  desc "Complete implementation of {{mustache}} templates using modern C++"
  homepage "https://github.com/no1msd/mstch"
  url "https://github.com/no1msd/mstch/archive/1.0.2.tar.gz"
  sha256 "811ed61400d4e9d4f9ae0f7679a2ffd590f0b3c06b16f2798e1f89ab917cba6c"
  revision 200

  depends_on "cmake" => :build
  depends_on "boost"

  def install
    system "cmake", ".", *std_cmake_args
    system "make", "install"

    (lib/"pkgconfig/mstch.pc").write pc_file
  end

  def pc_file; <<-EOS.undent
    prefix=#{HOMEBREW_PREFIX}
    exec_prefix=${prefix}
    libdir=${exec_prefix}/lib
    includedir=${exec_prefix}/include

    Name: mstch
    Description: Complete implementation of {{mustache}} templates using modern C++
    Version: 1.0.1
    Libs: -L${libdir} -lmstch
    Cflags: -I${includedir}
    EOS
  end
end
