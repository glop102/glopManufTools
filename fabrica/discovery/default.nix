{ buildPythonPackage, setuptools, pydantic, scapy, tkinter }:
buildPythonPackage {
  pname = "fabrica-discovery";
  version = "0.1.0";
  pyproject = true;
  src = ./.;
  build-system = [ setuptools ];
  dependencies = [ pydantic scapy tkinter ];
}
