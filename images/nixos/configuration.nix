{ config, pkgs, modulesPath, ... }:

{
  imports = [
    "${modulesPath}/profiles/minimal.nix"
    "${modulesPath}/profiles/qemu-guest.nix"
  ];

  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "ext4";
  };

  boot = {
    loader.grub.enable = false;

    kernelPackages = pkgs.linuxPackages_latest;
    kernelParams = [
      "console=ttyS0"
      "root=/dev/vda"
      "rw"
      "quiet"
    ];

    # Keep initrd enabled for reliable rootfs mounting on this image.
    initrd = {
      availableKernelModules = [
        "virtio_pci"
        "virtio_blk"
        "virtio_net"
      ];
      kernelModules = [ ];
    };

    kernelModules = [
      "virtio_pci"
      "virtio_blk"
      "virtio_net"
    ];
  };

  networking = {
    hostName = "minion";
    useDHCP = false;
    useNetworkd = false;
    firewall.enable = false;
  };

  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
    };
  };

  systemd.tmpfiles.rules = [
    "d /root/.ssh 0700 root root -"
  ];

  systemd.services = {
    "getty@tty1".enable = false;
    "getty@tty2".enable = false;
    "getty@tty3".enable = false;
    "getty@tty4".enable = false;
    "getty@tty5".enable = false;
    "getty@tty6".enable = false;
    "serial-getty@ttyS0".enable = true;
  };

  environment.systemPackages = with pkgs; [
    git
    curl
    wget
    vim
    nano
    htop
    unzip
  ];

  documentation.enable = false;

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

  users.users.root.hashedPassword = "!";
  system.stateVersion = "24.11";
}
