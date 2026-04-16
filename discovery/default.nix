{ buildPythonPackage, setuptools, pydantic, scapy, tkinter }:
buildPythonPackage {
  pname = "discovery";
  version = "0.1.0";
  pyproject = true;
  src = ./.;
  build-system = [ setuptools ];
  dependencies = [ pydantic scapy tkinter ];
}
