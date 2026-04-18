final: prev: {
  pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
    (python-final: python-prev: {
      fabrica_discovery = python-final.callPackage ./fabrica/discovery/default.nix { };
    })
  ];
  discovery-applet = final.python3Packages.callPackage ./discovery_applet/default.nix { };
}
