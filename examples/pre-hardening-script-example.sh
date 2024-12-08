#!/usr/bin/env bash

# Example tailoring file.
# CIS Level: 2
# Machine type: LXD

sudo pro enable usg
sudo apt install -y usg

# Rule ID: xccdf_org.ssgproject.content_rule_partition_for_tmp
# Rule name: Ensure /tmp Located On Separate Partition
# Tailoring action: Apply remediation
# Tailoring rationale: mount /tmp on a separate partition, do not change /dev/shm
grep 'tmpfs /tmp' /etc/fstab || echo "tmpfs /tmp tmpfs defaults,nodev,nosuid 0 0" >>/etc/fstab

# Rule ID: xccdf_org.ssgproject.content_rule_sshd_limit_user_access
# Rule name: Limit Users' SSH Access
# Tailoring action: Apply remediation
# Tailoring rationale: Allow SSH access to 'ubuntu' and 'root' users only.
tee /etc/ssh/sshd_config.d/canonical-cis-remediation-sshd_limit_user_access.conf << EOF
AllowUsers root ubuntu
AllowGroups root ubuntu
EOF

# Rule ID: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects
# Rule name: Disable Accepting ICMP Redirets for All IPv4 Interfaces
# Tailoring action: Apply Remediation
# Tailoring rationale: For any LXD container hosted by this server to also pass this rule, we need net.core.devconf_inherit_init_net = 1 in the host OS.
sysctl -w net.core.devconf_inherit_init_net 1
echo "# cis hardening xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects" > /etc/sysctl.d/99-cis-icmp-redirect-remediation
echo net.core.devconf_inherit_init_net = 1 >> /etc/sysctl.d/99-cis-icmp-redirect-remediation
