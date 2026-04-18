{ buildPythonApplication, setuptools, pyqt6, fabrica_discovery }:
buildPythonApplication {
  pname = "discovery-applet";
  version = "0.1.0";
  pyproject = true;
  src = ./.;
  build-system = [ setuptools ];
  dependencies = [ pyqt6 fabrica_discovery ];
}
