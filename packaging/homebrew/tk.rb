class Tk < Formula
  desc "Git signing and SSH for agents, with keys that never leave Turnkey"
  homepage "https://github.com/tkhq/tk"
  license "Apache-2.0"

  on_macos do
    depends_on arch: :arm64

    on_arm do
      url "https://github.com/tkhq/tk/releases/download/v@VERSION@/tk-aarch64-apple-darwin-v@VERSION@.tar.gz"
      sha256 "@SHA256_aarch64-apple-darwin@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/tkhq/tk/releases/download/v@VERSION@/tk-aarch64-unknown-linux-musl-v@VERSION@.tar.gz"
      sha256 "@SHA256_aarch64-unknown-linux-musl@"
    end
    on_intel do
      url "https://github.com/tkhq/tk/releases/download/v@VERSION@/tk-x86_64-unknown-linux-musl-v@VERSION@.tar.gz"
      sha256 "@SHA256_x86_64-unknown-linux-musl@"
    end
  end

  def install
    bin.install "tk"
  end

  test do
    assert_equal "tk #{version}\n", shell_output("#{bin}/tk --version")
  end
end
