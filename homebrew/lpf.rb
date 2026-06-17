class Lpf < Formula
  desc "OCaml-first PF-style control plane for Linux networking"
  homepage "https://github.com/avkcode/lpf"
  url "https://github.com/avkcode/lpf/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  depends_on "ocaml" => :build
  depends_on "opam" => :build
  depends_on "dune" => :build

  def install
    system "opam", "init", "--disable-sandboxing", "--no-setup"
    system "opam", "install", ".", "--deps-only", "--with-test"
    system "opam", "exec", "--", "dune", "build", "@install"
    system "opam", "exec", "--", "dune", "install", "--prefix=#{prefix}"
  end

  test do
    system "#{bin}/lpf", "version"
  end
end
