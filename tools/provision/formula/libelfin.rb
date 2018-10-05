require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libelfin < AbstractOsqueryFormula
  desc "libelfin"
  homepage "https://github.com/aclements/libelfin"
  license "MIT"
  url "https://github.com/aclements/libelfin/archive/v0.3.tar.gz"
  sha256 "c338942b967582922b3514b54b93175ca9051a9668db92dd8ef619824d443ac7"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "5cf956b4999246cd2c78ccd389456250e42f8b42428c6d9e1af5eb9d059b90fb" => :x86_64_linux
  end

  def install
    system "make", "install", "PREFIX=#{prefix}"
  end
end
