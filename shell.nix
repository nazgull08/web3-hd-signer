with import ./nix/pkgs.nix {};
let merged-openssl = symlinkJoin { name = "merged-openssl"; paths = [ openssl.out openssl.dev ]; };
in stdenv.mkDerivation rec {
  name = "web3-hd";
  env = buildEnv { name = name; paths = buildInputs; };

  buildInputs = [
    rustup
    openssl
    cmake
  ];
  shellHook = ''
  export OPENSSL_DIR="${merged-openssl}"
  '';
}
