{
  lib,
  buildPythonPackage,
  hatchling,
  anyio,
  argon2-cffi,
  cryptography,
  fido2,
  httpx2,
  pydantic,
}:
# A package, not an application: `withPackages` drops an application, and
# the tests import this one. default.nix makes the application of it.
buildPythonPackage (finalAttrs: {
  pname = "touchgate";
  version = "0.1.0";
  pyproject = true;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../pyproject.toml
      ../README.md
      ../LICENSE
      (lib.fileset.fileFilter (file: file.hasExt "py" || file.name == "py.typed") ../src)
    ];
  };

  build-system = [ hatchling ];
  dependencies = [
    anyio
    argon2-cffi
    cryptography
    fido2
    httpx2
    pydantic
  ];

  pythonImportsCheck = [ "touchgate" ];

  meta = {
    description = "Run a command with secrets from a Bitwarden vault once a hardware key touch approves it";
    homepage = "https://github.com/Lillecarl/touchgate";
    license = lib.licenses.asl20;
    mainProgram = "touchgate";
  };
})
