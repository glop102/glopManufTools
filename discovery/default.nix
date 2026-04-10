{ buildPythonPackage, hatchling, pydantic, scapy, lib }:
buildPythonPackage {
  pname = "discovery";
  version = "0.1.0";
  pyproject = true;
  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type: lib.hasPrefix (toString ../discovery) path;
  };
  build-system = [ hatchling ];
  dependencies = [ pydantic scapy ];
}
