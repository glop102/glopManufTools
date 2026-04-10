final: prev: {
  pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
    (python-final: python-prev: {
      discovery = python-final.callPackage ./discovery/default.nix { };
    })
  ];
  discovery-applet = final.python3Packages.callPackage ./discovery_applet/default.nix { };
}
