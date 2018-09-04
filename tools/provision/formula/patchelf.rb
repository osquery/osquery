require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Patchelf < AbstractOsqueryFormula
  desc "Modify dynamic ELF executables"
  homepage "https://nixos.org/patchelf.html"
  url "https://nixos.org/releases/patchelf/patchelf-0.9/patchelf-0.9.tar.gz"
  sha256 "f2aa40a6148cb3b0ca807a1bf836b081793e55ec9e5540a5356d800132be7e0a"
  revision 1 unless OS.mac?

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any
    sha256 "00c02e6c700f4427da40a82e2a5d88427cfb28a79b3ac69f441d69d8377254f4" => :x86_64_linux # glibc 2.5
  end

  option "with-static", "Link statically"
  option "without-static-libstdc++", "Link libstdc++ dynamically"

  def install
    # Fixes error: cannot find section
    # See https://github.com/NixOS/patchelf/pull/95
    inreplace "src/patchelf.cc",
      "string sectionName = getSectionName(shdr);",
      'string sectionName = getSectionName(shdr); if (sectionName == "") continue;'
    system "./bootstrap.sh" if build.head?
    system "./configure", "--prefix=#{prefix}",
      if build.with?("static") then "CXXFLAGS=-static"
      elsif build.with?("static-libstdc++") then "CXXFLAGS=-static-libgcc -static-libstdc++"
      end,
      "--disable-debug",
      "--disable-dependency-tracking",
      "--disable-silent-rules"
    system "make", "install"
  end

end
