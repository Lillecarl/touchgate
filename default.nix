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
  module = python.pkgs.callPackage ./nix/package.nix { };
  touchgate = python.pkgs.toPythonApplication module;
in
{
  inherit touchgate;
  default = touchgate;

  shell = pkgs.callPackage ./nix/shell.nix {
    inherit python;
    touchgate = module;
  };
  # callPackages, not callPackage: the latter adds `override` to the set.
  checks = pkgs.callPackages ./nix/checks.nix {
    inherit python;
    touchgate = module;
  };
  formatter = pkgs.nixfmt-tree;
}
