let
  sources = import ./nix/sources.nix;
  nixpkgs-mozilla = import sources.nixpkgs-mozilla;
  pkgs = import sources.nixpkgs {
    overlays =
      [
        nixpkgs-mozilla
        (self: super:
            let chan = self.rustChannelOf { date = "2023-04-12"; channel = "nightly"; };
            in {
              rustc = chan.rust;
              cargo = chan.rust;
            }
        )
      ];
  };
  naersk = pkgs.callPackage sources.naersk {};
  merged-openssl = pkgs.symlinkJoin { name = "merged-openssl"; paths = [ pkgs.openssl.out pkgs.openssl.dev ]; };
in
naersk.buildPackage {
  name = "web3-hd-signer";
  root = pkgs.lib.sourceFilesBySuffices ./. [".rs" ".toml" ".lock" ".html" ".css" ".png" ".sh" ".sql" ".proto" ".json" ];
  buildInputs = with pkgs; [ cmake protobuf sqlx-cli openssl pkgconfig clang llvm llvmPackages.libclang zlib cacert curl postgresql pkg-config gpgme libgpg-error libgpg-error.dev gnupg];
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang}/lib";
  OPENSSL_DIR = "${merged-openssl}";
  PKG_CONFIG_PATH = "${pkgs.libgpg-error.dev}/lib/pkgconfig";
  preBuild = ''
  '';
}
