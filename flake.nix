{
  description = "touchgate: run a command with vault secrets once a hardware key touch approves it";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Read by nix/compat.nix, so default.nix uses this same lock.
    flake-compatish.url = "github:lillecarl/flake-compatish";
  };

  # A wrapper. Every output is an attribute of default.nix.
  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      perSystem = lib.genAttrs systems (system: import ./default.nix { inherit inputs system; });
      forAllSystems = f: lib.mapAttrs (_: f) perSystem;
    in
    {
      packages = forAllSystems (p: {
        inherit (p) default touchgate;
      });
      devShells = forAllSystems (p: {
        default = p.shell;
      });
      checks = forAllSystems (p: p.checks);
      formatter = forAllSystems (p: p.formatter);
    };
}
