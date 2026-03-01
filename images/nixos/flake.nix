{
  description = "NixOS VM image for Minions with built-in agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      # Build the NixOS image and extract the kernel
      packages.${system} = {
        # The main NixOS image
        nixos-image = self.nixosConfigurations.minions-vm.config.system.build.raw;

        # Extracted vmlinux kernel for Cloud Hypervisor
        kernel = pkgs.runCommand "extract-vmlinux" { } ''
          mkdir -p $out
          cp ${self.nixosConfigurations.minions-vm.config.boot.kernelPackages.kernel.dev}/vmlinux $out/vmlinux
        '';

        # Default: build both image and kernel
        default = pkgs.runCommand "minions-nixos" { } ''
          mkdir -p $out
          cp ${self.packages.${system}.nixos-image}/nixos.img $out/base-nixos.ext4
          cp ${self.packages.${system}.kernel}/vmlinux $out/vmlinux-nixos
        '';
      };

      # NixOS configuration
      nixosConfigurations.minions-vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./configuration.nix
          # Agent module will be added here after we have the pre-built binary
          # For now, the agent is expected to be injected post-build
        ];
      };
    };
}
