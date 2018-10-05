require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class FbthriftDoubleConversion < AbstractOsqueryFormula
  desc "Binary-decimal and decimal-binary routines for IEEE doubles"
  homepage "https://github.com/floitsch/double-conversion"
  url "https://github.com/floitsch/double-conversion/archive/v1.1.5.tar.gz"
  sha256 "03b976675171923a726d100f21a9b85c1c33e06578568fbc92b13be96147d932"
  revision 200

  def install
    mkdir "dc-build" do
      system "cmake", "..", *osquery_cmake_args
      system "make", "install"
    end
  end
end
