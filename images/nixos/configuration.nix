{ config, pkgs, lib, modulesPath, ... }:

{
  imports = [
    "${modulesPath}/profiles/minimal.nix"
    "${modulesPath}/profiles/qemu-guest.nix"
  ];

  # Filesystem configuration
  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "ext4";
    autoResize = true;
  };

  # Boot configuration - Cloud Hypervisor does direct kernel boot
  boot = {
    # No bootloader needed - Cloud Hypervisor boots vmlinux directly
    loader.grub.enable = false;

    # Kernel must have virtio drivers built-in (not as modules)
    # Cloud Hypervisor boots without initramfs
    kernelPackages = pkgs.linuxPackages_latest;
    kernelParams = [
      "console=ttyS0"
      "root=/dev/vda"
      "rw"
      "quiet"
    ];

    # Include essential virtio drivers in kernel
    kernelModules = [ ];
    initrd.enable = false;

    # Ensure virtio modules are built into kernel, not as modules
    kernelPatches = [{
      name = "virtio-builtin";
      patch = null;
      extraStructuredConfig = with lib.kernel; {
        VIRTIO = yes;
        VIRTIO_BLK = yes;
        VIRTIO_NET = yes;
        VIRTIO_VSOCKETS = yes;
        VSOCKETS = yes;
      };
    }];
  };

  # Networking - agent configures via imperative commands
  networking = {
    hostName = "minion";
    useDHCP = false;
    useNetworkd = false;
    # No firewall - VMs are isolated via bridge port isolation
    firewall.enable = false;
  };

  # SSH configuration
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
    };
  };

  # Create /root/.ssh for authorized_keys injection
  systemd.tmpfiles.rules = [
    "d /root/.ssh 0700 root root -"
  ];

  # Disable unnecessary getty services to save RAM (~13 MB)
  systemd.services = {
    "getty@tty1".enable = false;
    "getty@tty2".enable = false;
    "getty@tty3".enable = false;
    "getty@tty4".enable = false;
    "getty@tty5".enable = false;
    "getty@tty6".enable = false;
    "serial-getty@ttyS0".enable = true; # Keep serial console for debugging
  };

  # Minimal package set
  environment.systemPackages = with pkgs; [
    git
    curl
    wget
    vim
    nano
    htop
    unzip
  ];

  # No documentation to save space
  documentation.enable = false;

  # Optimize for size
  environment.noXlibs = true;

  # Minions agent systemd service
  # Note: The agent binary itself is injected during the build script
  systemd.services.minions-agent = {
    description = "Minions Guest Agent";
    after = [ "systemd-modules-load.service" ];
    wants = [ "systemd-modules-load.service" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "/usr/local/bin/minions-agent";
      Restart = "always";
      RestartSec = "1";
      StandardOutput = "journal";
      StandardError = "journal";
    };
  };

  # Disable root password
  users.users.root.hashedPassword = "!";

  # System state version
  system.stateVersion = "24.11";

  # Image format configuration
  image.repart.name = "nixos";
  formatAttr = "raw";
}
