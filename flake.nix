{
  description = "A devShell example";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [
          (import rust-overlay)
          (_: prev: {
            compactc = prev.callPackage ./nix/compactc.nix { };
          })
        ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
          targets = [ ];
        };
      in
      {
        devShells.default =
          let
            rootDir = "$ROOT_DIR";
            scripts = {
              format = pkgs.writeShellApplication {
                name = "format";
                runtimeInputs = with pkgs; [
                  nixfmt
                  taplo
                ];
                text = ''
                  cd "${rootDir}"
                  find . | grep '\.nix$' | xargs -I _ bash -c "echo running nixfmt on _ && nixfmt _"
                  find . | grep '\.toml$' | xargs -I _ bash -c "echo running taplo on _ && taplo format _"
                  ${rust}/bin/cargo fmt
                '';
              };
            };
          in
          pkgs.mkShell {
            packages =
              (with pkgs; [
                # base
                git
                less
                ncurses
                pkg-config
                which
                openssl
                # rust
                rust
                # midnight-js
                compactc
                nodejs_22
                typescript
                nodePackages.typescript-language-server
              ])
              ++ (builtins.attrValues scripts);

            shellHook = ''
              export ROOT_DIR=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
              export COMPACT_HOME="${pkgs.compactc}/bin"
              ${pkgs.cowsay}/bin/cowsay "Working on project root directory: ${rootDir}"
              cd ${rootDir}
            '';
          };
      }
    );
}
