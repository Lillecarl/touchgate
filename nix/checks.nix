{
  lib,
  runCommand,
  cacert,
  python,
  touchgate,
  vaultwarden,
  bitwarden-cli,
  openssh,
  ruff,
  pyrefly,
  nixfmt,
}:
let
  root = ../.;

  pythonSources = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      ../pyproject.toml
      ../pyrefly.toml
      (lib.fileset.fileFilter (file: file.hasExt "py") ../src)
      (lib.fileset.fileFilter (file: file.hasExt "py") ../tests)
    ];
  };

  testEnv = python.withPackages (
    ps:
    touchgate.dependencies
    ++ [
      touchgate
      ps.pytest
      ps.pytest-timeout
      ps.trustme
    ]
  );

  # OpenSSH's signature vectors, made by OpenSSH with its test security keys.
  sshsigVectors = runCommand "sshsig-vectors" { } ''
    tar -xf ${openssh.src}
    cp -r */regress/unittests/sshsig/testdata $out
  '';

  # Narrows a run while iterating: `TOUCHGATE_TESTS=tests/test_x.py nix build --impure --file . checks.tests`.
  selected = builtins.getEnv "TOUCHGATE_TESTS";
in
{
  inherit touchgate;

  # The tests read the package installed in testEnv, not the source tree.
  # vaultwarden is the server, and the official `bw` writes the fixtures,
  # so touchgate never judges a vault it wrote itself.
  tests =
    runCommand "touchgate-tests"
      {
        nativeBuildInputs = [
          testEnv
          vaultwarden
          bitwarden-cli
          openssh
        ];
      }
      ''
        cp -r ${pythonSources} src && chmod -R +w src && cd src
        export HOME=$TMPDIR
        export TOUCHGATE_SSHSIG_VECTORS=${sshsigVectors}
        # httpx2 builds a TLS context even for http://, and the sandbox has no CA file.
        export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
        python -m pytest -p no:cacheprovider --import-mode=importlib -v ${
          if selected == "" then "tests" else selected
        }
        touch $out
      '';

  ruff = runCommand "touchgate-ruff" { nativeBuildInputs = [ ruff ]; } ''
    cd ${pythonSources}
    ruff check --no-cache .
    ruff format --no-cache --check .
    touch $out
  '';

  pyrefly =
    runCommand "touchgate-pyrefly"
      {
        nativeBuildInputs = [
          testEnv
          pyrefly
        ];
      }
      ''
        cp -r ${pythonSources} src && chmod -R +w src && cd src
        pyrefly check --python-interpreter-path ${testEnv}/bin/python
        touch $out
      '';

  nixfmt =
    runCommand "touchgate-nixfmt"
      {
        nativeBuildInputs = [ nixfmt ];
        src = lib.fileset.toSource {
          inherit root;
          fileset = lib.fileset.fileFilter (file: file.hasExt "nix") root;
        };
      }
      ''
        find "$src" -name '*.nix' -exec nixfmt --check {} +
        touch $out
      '';
}
