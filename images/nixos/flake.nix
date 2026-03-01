{
  description = "NixOS VM image for Minions with built-in agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # Build a raw ext4 disk image for Cloud Hypervisor.
      makeImage = import "${nixpkgs}/nixos/lib/make-disk-image.nix" {
        inherit pkgs;
        lib = nixpkgs.lib;
        config = self.nixosConfigurations.minions-vm.config;
        diskSize = 5120; # 5GB in MB
        format = "raw";
        partitionTableType = "none";
      };
    in
    {
      packages.${system} = {
        # Raw disk image (ext4)
        nixos-image = makeImage;

        # vmlinux for Cloud Hypervisor
        kernel = pkgs.runCommand "extract-vmlinux" { } ''
          mkdir -p $out
          cp ${self.nixosConfigurations.minions-vm.config.boot.kernelPackages.kernel.dev}/vmlinux $out/vmlinux
        '';

        # initramfs required by this NixOS configuration
        initramfs = pkgs.runCommand "extract-initrd" { } ''
          mkdir -p $out
          cp ${self.nixosConfigurations.minions-vm.config.system.build.initialRamdisk}/initrd $out/initrd
        '';

        # Bundle artifacts expected by scripts/build-nixos-image.sh
        default = pkgs.runCommand "minions-nixos" { } ''
          mkdir -p $out
          cp ${self.packages.${system}.nixos-image}/nixos.img $out/base-nixos.ext4
          cp ${self.packages.${system}.kernel}/vmlinux $out/vmlinux-nixos
          cp ${self.packages.${system}.initramfs}/initrd $out/initrd-nixos
        '';
      };

      nixosConfigurations.minions-vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./configuration.nix
        ];
      };
    };
}
