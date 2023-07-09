# To update nix-prefetch-git https://github.com/NixOS/nixpkgs
import ((import <nixpkgs> {}).fetchFromGitHub {
  owner = "NixOS";
  repo = "nixpkgs";
  rev = "e92e5835ca3016a1fc9a8e571d4e01d3e514acbf";
  sha256  = "04pfs4klmzp1a6m6g2p733f2c69jagvsmwgznabwx8facyg4pmq8";
})
