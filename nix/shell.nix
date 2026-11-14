{
  mkShell,
  python,
  touchgate,
  vaultwarden,
  bitwarden-cli,
  ruff,
  pyrefly,
}:
mkShell {
  packages = [
    (python.withPackages (
      ps:
      touchgate.dependencies
      ++ [
        ps.pytest
        ps.pytest-timeout
      ]
    ))
    vaultwarden
    bitwarden-cli
    ruff
    pyrefly
  ];
}
