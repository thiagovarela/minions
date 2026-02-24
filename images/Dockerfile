FROM ubuntu:24.04

# Update packages and install base tools + development utilities
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      systemd \
      systemd-sysv \
      dbus \
      dbus-user-session \
      openssh-server \
      iproute2 \
      iputils-ping \
      curl \
      wget \
      ca-certificates \
      sudo \
      git \
      vim \
      nano \
      htop \
      unzip \
      build-essential \
    && rm -rf /var/lib/apt/lists/*

# SSH server setup
RUN mkdir -p /run/sshd && \
    systemctl enable ssh

# SSH: key-based auth only
RUN passwd -l root && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Serial console for debugging (accessible via `minions logs`)
RUN mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d && \
    printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %%I 115200 linux\n' \
      > /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf && \
    systemctl enable serial-getty@ttyS0.service

RUN echo 'minion' > /etc/hostname
