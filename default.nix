let
  compat = import ./nix/compat.nix;
in
{
  inputs ? compat.inputs,
  system ? builtins.currentSystem,
  pkgs ? import inputs.nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  },
}:
let
  python = pkgs.python3;
  touchgate = python.pkgs.callPackage ./nix/package.nix { };
in
{
  inherit touchgate;
  default = touchgate;

  shell = pkgs.callPackage ./nix/shell.nix { inherit touchgate python; };
  # callPackages, not callPackage: the latter adds `override` to the set.
  checks = pkgs.callPackages ./nix/checks.nix { inherit touchgate python; };
  formatter = pkgs.nixfmt-tree;
}
