{
  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs?ref=nixos-unstable";
    };
  };
  outputs =
    { self, nixpkgs, ... }@flakeInputs:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      inherit nixpkgs;
      overlays = {
        default = import ./overlay.nix;
      };
      legacyPackages = forAllSystems (
        system: nixpkgs.legacyPackages.${system}.appendOverlays (builtins.attrValues self.overlays)
      );
      # TODO tree formatter to also hit up the ruff formatter
      formatter = forAllSystems (system: self.legacyPackages.${system}.nixfmt-tree);
      packages = forAllSystems (system: {
        inherit (self.legacyPackages.${system}) discovery-applet;
        default = self.legacyPackages.${system}.discovery-applet;
      });
      apps = forAllSystems (system: {
        discovery-applet = {
          type = "app";
          program = "${self.legacyPackages.${system}.discovery-applet}/bin/discovery-applet";
        };
        default = self.apps.${system}.discovery-applet;
      });
      devShells = forAllSystems (
        system:
        (
          let
            pkgs = self.legacyPackages.${system};
            pythonPackages = pkgs.python3Packages;
          in
          {
            # https://nixos.org/manual/nixpkgs/stable/#how-to-consume-python-modules-using-pip-in-a-virtual-environment-like-i-am-used-to-on-other-operating-systems
            default = pkgs.mkShell {
              name = "manuf tools dev shell";
              #venvDir = "./.venv";
              buildInputs =
                (with pkgs; [
                ])
                ++ (with pythonPackages; [
                  python
                  ruff
                  #venvShellHook
                  requests
                  scapy
                  tkinter
                  pydantic
                  pytest
                  pytest-cov
                  pyqt6
                ]);
              shellHook = ''
                export PS1='\n(dev) \[\033[1;32m\][\[\e]0;\u@\h: \w\a\]\u@\h:\w]\$\[\033[0m\] '
                # TODO add to the module search path fo use our local folders
                export PYTHONPATH=$(pwd):$PYTHONPATH
              '';
            };
          }
        )
      );
    };
}
