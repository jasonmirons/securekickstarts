#!/usr/bin/env python
#
# Copyright 2013 Major Hayden
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

# 2019 Modified by lnxdork for centos7 based on CIS CentOS Linux 7 Benchmark v2.2.0 - 12-27-2017
# TODO: Check CIS numbering and requirements for centos/RHEL 7
#       grub2-setpassword 1.4.2
#       grub2-mkconfig -o /boot/grub2/grub.cfg 1.4.2
#       1.6.1.1
#       1.6.1.6
#       2.2.1.3
#       2.2.15
#       3.4.2
#       4.1.3
#       Create versions for centos/RHEL 8

install
url --url=http://mirrors.kernel.org/centos/7/os/x86_64/
text
lang en_US.UTF-8
keyboard us
network --onboot yes --device eth0 --bootproto dhcp --ipv6 auto
rootpw qwerty

# CIS 4.7
firewall --enabled --ssh

# CIS 6.3.1
authconfig --enableshadow --passalgo=sha512

# CIS 1.6.1.2 - 1.6.1.3(targeted is enabled by default w/enforcing)
selinux --enforcing

timezone --utc America/Chicago
services --enabled network,sshd
zerombr

clearpart --all
part /boot --fstype=xfs --size=250
part swap --size=1024
# LUKS encrypt the root volume, it will prompt for password on install.
part pv.01 --size=1 --grow --encrypted
volgroup vg_root pv.01
logvol / --vgname vg_root --name root --fstype=xfs --size=10240
# CIS 1.1.2-1.1.5
logvol /tmp --vgname vg_root --name tmp --size=500 --fsoptions="rw,nosuid,nodev,noexec,relatime"
# CIS 1.1.6
logvol /var --vgname vg_root --name var --size=500
# CIS 1.1.7-1.1.10
logvol /var/tmp --vgname vg_root --name var_tmp --size=500 --fsoptions="rw,nosuid,nodev,noexec,relatime"
# CIS 1.1.11
logvol /var/log --vgname vg_root --name log --size=1024
# CIS 1.1.12
#logvol /var/log/audit --vgname vg_root --name audit --size=1024 --fsoptions="rw,relatime,data=ordered"
logvol /var/log/audit --vgname vg_root --name audit --size=1024 --fsoptions="rw,relatime"
# CIS 1.1.13-1.1.14
logvol /home --vgname vg_root --name home --size=1024 --grow --fsoptions="nodev"


# CIS 5.2.3
bootloader --location=mbr --driveorder=vda --append="selinux=1 audit=1"
reboot

%packages
@core
setroubleshoot-server
aide                        # CIS 1.3.1
selinux-policy-targeted     # CIS 1.6.1.3
-setroubleshoot             # CIS 1.6.1.4
-mcstrans                   # CIS 1.6.1.5
-prelink                    # CIS 1.5.4 <-
-telnet-server              # CIS 2.1.1
-telnet                     # CIS 2.3.4
-rsh-server                 # CIS 2.1.3
-rsh                        # CIS 2.3.2
-ypbind                     # CIS 2.3.1
-ypserv                     # CIS 2.1.6
-tftp                       # CIS 2.1.7
-tftp-server                # CIS 2.1.8
-talk-server                # CIS 2.3.3
-openldap-clients           # CIS 2.3.5
-xinetd                     # CIS 2.1.11
# -@"X Window System"       # CIS 3.2
-xorg-x11*                  # CIS 2.2.2
-avahi-daemon               # CIS 2.2.3
-dhcp                       # CIS 3.5
-ntp                        # CIS 2.2.1.1 
chrony                      # CIS 2.2.1.1 
postfix                     # CIS 3.16
# syslog-ng                   # CIS 4.2.3
rsyslog                     # CIS 4.2.3
cronie-anacron              # CIS 6.1.1
tcp_wrappers                # CIS 3.4
iptables                    # CIS 3.6.1
# pam_passwdqc              # CIS 6.3.3
clevis                      # Optional, for FDE and pre-boot auth
# dig                         # Optional, for Lynis 
%end

%post --log=/root/postinstall.log

###############################################################################
# CIS 1.1.1.1
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS 1.1.1.2
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS 1.1.1.3
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS 1.1.1.4
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS 1.1.1.5
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS 1.1.1.6
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS 1.1.1.7
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
# CIS 1.1.1.7
echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf

# /etc/fstab
echo -e "\n# CIS Benchmark Adjustments" >> /etc/fstab
# CIS 1.1.6
# echo "/tmp      /var/tmp    none    bind    0 0" >> /etc/fstab

# CIS 1.1.15-1.1.17
awk '$2~"^/dev/shm$"{$4="nodev,noexec,nosuid"}1' OFS="\t" /etc/fstab >> /tmp/fstab
mv /tmp/fstab /etc/fstab
restorecon -v /etc/fstab && chmod 644 /etc/fstab

# CIS 1.2.3
sed -i 's/gpgcheck=.*$/gpgcheck=1/' /etc/yum.conf
sed -i 's/gpgcheck=.*$/gpgcheck=1/g' /etc/yum.repos.d/*

# CIS 1.3.1
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# CIS 1.3.2
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root

# CIS 1.4.2
sed -i "/^CLASS=/s/ --unrestricted//" /etc/grub.d/10_linux

# CIS 1.4.3
ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-blockdefault"

# CIS 1.5.1
echo "* hard core 0" >> /etc/security/limits.conf
sysctl -w fs.suid_dumpable=0

# CIS 1.5.5
sed -i 's/^PROMPT=yes$/PROMPT=no/' /etc/sysconfig/init

###############################################################################
# /etc/sysctl.conf
cat << 'EOF' >> /etc/sysctl.conf

# CIS Benchmark Adjustments
fs.suid_dumpable = 0                                    # CIS 1.5.1
kernel.exec-shield = 1                                  # CIS 1.6.2
kernel.randomize_va_space = 2                           # CIS 1.5.3
net.ipv4.ip_forward = 0                                 # CIS 3.1.1
net.ipv4.conf.all.send_redirects = 0                    # CIS 3.1.2
net.ipv4.conf.default.send_redirects = 0                # CIS 3.1.2
net.ipv4.conf.all.accept_source_route = 0               # CIS 3.2.1
net.ipv4.conf.default.accept_source_route = 0           # CIS 3.2.1
net.ipv4.conf.all.accept_redirects = 0                  # CIS 3.2.2
net.ipv4.conf.default.accept_redirects = 0              # CIS 3.2.2
net.ipv4.conf.all.secure_redirects = 0                  # CIS 3.2.3
net.ipv4.conf.default.secure_redirects = 0              # CIS 3.2.3
net.ipv4.conf.all.log_martians = 1                      # CIS 3.2.4
net.ipv4.conf.default.log_martians = 1                  # CIS 3.2.4
net.ipv4.icmp_echo_ignore_broadcasts = 1                # CIS 3.2.5
net.ipv4.icmp_ignore_bogus_error_responses = 1          # CIS 3.2.6
net.ipv4.conf.all.rp_filter = 1                         # CIS 3.2.7
net.ipv4.conf.default.rp_filter = 1                     # CIS 3.2.7
net.ipv4.tcp_syncookies = 1                             # CIS 3.2.8
EOF

###############################################################################
# /etc/dconf/profile/gdm
cat << 'EOF' >> /etc/dconf/profile/gdm

# CIS Benchmark Adjustments CIS 1.7.2
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

# /etc/dconf/db/gdm.d/01-banner-message
cat << 'EOF' >> /etc/dconf/db/gdm.d/01-banner-message

# CIS Benchmark Adjustments CIS 1.7.2
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized uses only. All activity may be monitored and reported.'
EOF

# /etc/audit/audit.conf
cat << 'EOF' >> /etc/audit/audit.conf

# CIS Benchmark Adjustments

# CIS 4.1.1.2
space_left_action = email
action_mail_acct = root
admin_space_left_action = halt

# CIS 4.1.1.3
max_log_file_action = keep_logs
EOF

# /etc/audit/audit.rules
cat << 'EOF' >> /etc/audit/audit.rules

# CIS Benchmark Adjustments

# CIS 4.1.4
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# CIS 4.1.5
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# CIS 4.1.6
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/syscondif/network-scripts/ -p wa -k system-locale

# CIS 4.1.7
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# CIS 4.1.8
-w /var/log/faillock -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# CIS 4.1.9
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# CIS 4.1.10
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# CIS 4.1.11
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# CIS 4.1.13
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# CIS 4.1.14
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# CIS 4.1.15
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# CIS 4.1.16
-w /var/log/sudo.log -p wa -k actions

# CIS 4.1.17
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

# CIS 4.1.12
echo -e "\n# CIS 5.2.12" >> /etc/audit/audit.rules
find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules

# CIS 4.1.18
echo -e "\n# CIS 5.2.18"
echo "-e 2" >> /etc/audit/audit.rules

# CIS 2.1.1
chkconfig chargen-dgram off
chkconfig chargen-stream off
# CIS 2.1.2
chkconfig daytime-dgram off
chkconfig daytime-stream off
# CIS 2.1.3
chkconfig discard-dgram off
chkconfig discard-stream off
# CIS 2.1.4
chkconfig echo-dgram off
chkconfig echo-stream off
# CIS 2.1.5
chkconfig time-dgram off
chkconfig time-stream off
# CIS 2.1.6
chkconfig tftp off
# CIS 2.1.7
systemctl disable xinetd

# CIS 2.1.18
chkconfig tcpmux-server off

# CIS 2.2.3
systemctl disable avahi-daemon

# CIS 3.1
echo "\n# CIS Benchmarks" 
echo "umask 027" >> /etc/sysconfig/init

# CIS 2.2.4
systemctl disable cups
# CIS 2.2.5
systemctl is-enabled dhcpd
# CIS 2.2.6
systemctl disable slapd
# CIS 2.2.7
systemctl disable nfs
systemctl disable nfs-server
systemctl disable rpcbind
# CIS 2.2.8
systemctl disable named
# CIS 2.2.9
systemctl disable vsftpd
# CIS 2.2.10
systemctl disable httpd
# CIS 2.2.11
systemctl disable dovecot
# CIS 2.2.12
systemctl disable sm
# CIS 2.2.13
systemctl disable squid
# CIS 2.2.14
systemctl disable snmpd
# CIS 2.2.16
systemctl disable ypserv
# CIS 2.2.17
systemctl disable rsh.socket
systemctl disable rlogin.socket
systemctl disable rexec.socket
# CIS 2.2.18
systemctl disable telnet.socket
# CIS 2.2.19
systemctl disable tftp.socket
# CIS 2.2.20
systemctl disable rsyncd
# CIS 2.2.22
systemctl disable ntalk

# CIS 4.1.2
systemctl enable auditd

# CIS 3.6 (ntp.conf defaults meet requirements)
chkconfig ntpd on
# CIS 3.16 (postfix defaults meet requirements)
chkconfig sendmail off
alternatives --set mta /usr/sbin/sendmail.postfix
chkconfig postfix on

# CIS 4.2.1
systemctl enable rsyslog

# CIS 4.2.1.3
sed -i 's/^\$FileCreateMode.*$/$FileCreateMode 0640/' /etc/rsyslog.conf
sed -i 's/^\$FileCreateMode.*$/$FileCreateMode 0640/g' /etc/rsyslog.d/*.conf

# Change the /etc/profile umask settings
sed -i 's/umask.*$/umask 077/g' /etc/profile
sed -i 's/umask.*$/umask 077/g' /etc/init.d/functions
sed -i 's/umask.*$/umask 077/g' /etc/bashrc
sed -i 's/umask.*$/umask 077/g' /etc/csh.cshrc

# Set a timeout setting in /etc/profile
cat << 'EOF' >> /etc/profile

# Set an idle timeout
TMOUT=300
readonly TMOUT
export TMOUT
EOF

# CIS 4.2.1.4
echo "*.* @@loghost.example.com" >> /etc/rsyslog.conf
echo "*.* @@loghost.example.com" >> /etc/rsyslog.d/*.conf

# CIS 4.2.2
systemctl enable syslog-ng

# CIS 4.2.2.3
echo "options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" >> /etc/syslog-ng/syslog-ng.conf

# CIS 4.2.4
find /var/log -type f -exec chmod g-wx,o-rwx {} +

# CIS 5.1.1
systemctl enable crond

# CIS 5.1.2
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

# CIS 5.1.3
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

# CIS 5.1.4
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

# CIS 5.1.5
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

# CIS 5.1.6
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

# CIS 5.1.7
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# CIS 5.1.8
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

# CIS 5.2.1
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

# CIS 3.4.2
echo "# ALL: <net>/<mask>, <net>/<mask>, ..." >>/etc/hosts.allow
# CIS 3.4.3
echo "ALL: ALL" >> /etc/hosts.deny
# CIS 3.4.4
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
# CIS 3.4.5
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

# CIS 3.6.2
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
# CIS 3.6.3
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
# CIS 3.6.4
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# CIS 3.6.5
iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT

# CIS 5.2.2
sed -i 's/Protocol.*$/Protocol 2/' /etc/ssh/sshd_config
# CIS 5.2.3
sed -i 's/LogLevel.*$/LogLevel INFO/' /etc/ssh/sshd_config
# CIS 5.2.4
sed -i 's/^#X11Forwarding no$/X11Forwarding no/' /etc/ssh/sshd_config
sed -i '/^X11Forwarding yes$/d' /etc/ssh/sshd_config
# CIS 5.2.5
sed -i 's/^.*MaxAuthTries.*$/MaxAuthTries 4/' /etc/ssh/sshd_config
# CIS 5.2.6
sed -i 's/^.*IgnoreRhosts.*$/IgnoreRhosts yes/' /etc/ssh/sshd_config
# CIS 5.2.7
sed -i 's/^.*HostbasedAuthentication.*$/HostbasedAuthentication no' /etc/ssh/sshd_config
# CIS 5.2.8
sed -i 's/^#PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
# CIS 5.2.9
sed -i 's/^#PermitEmptyPasswords.*$/PermitEmptyPasswords no' /etc/ssh/sshd_config
# CIS 5.2.10
sed -i 's/^#PermitUserEnvironment.*$/PermitUserEnvironment no' /etc/ssh/sshd_config
# CIS 5.2.11
echo -e "\n# CIS Benchmarks\n# CIS 6.2.12" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
# CIS 5.2.12
sed -i 's/^.*ClientAliveInterval.*$/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^.*ClientAliveCountMax.*$/ClientAliveCountMax 0/' /etc/ssh/sshd_config
# CIS 5.2.13
sed -i 's/^.*LoginGraceTime.*$/LoginGraceTime 60/' /etc/ssh/sshd_config
# CIS 5.2.14
echo "AllowUsers <userlist>" >> /etc/ssh/sshd_config
echo "AllowGroups <grouplist>" >> /etc/ssh/sshd_config
echo "DenyUsers <userlist>" >> /etc/ssh/sshd_config
echo "DenyGroups <grouplist>" >> /etc/ssh/sshd_config
# CIS 5.2.15
echo "Unauthorized access is prohibited." > /etc/ssh/sshd_banner
echo -e "\n# CIS 6.2.14" >> /etc/ssh/sshd_config
echo "Banner /etc/ssh/sshd_banner" >> /etc/ssh/sshd_config 

# CIS 5.3.1
sed -i 's/password.+requisite.+pam_cracklib.so/password required pam_cracklib.so try_first_pass retry=3' /etc/pam.d/system-auth
echo"minlen = 14" >> /etc/security/pwquality.conf
echo"dcredit = -1" >> /etc/security/pwquality.conf
echo"ucredit = -1" >> /etc/security/pwquality.conf
echo"ocredit = -1" >> /etc/security/pwquality.conf
echo"lcredit = -1" >> /etc/security/pwquality.conf

# CIS 6.3.3
sed -i -e '/pam_cracklib.so/{:a;n;/^$/!ba;i\password    requisite     pam_passwdqc.so min=disabled,disabled,16,12,8' -e '}' /etc/pam.d/system-auth
# CIS 6.3.6
sed -i 's/^\(password.*sufficient.*pam_unix.so.*\)$/\1 remember=5/' /etc/pam.d/system-auth
# CIS 6.5
sed -i 's/^#\(auth.*required.*pam_wheel.so.*\)$/\1/' /etc/pam.d/su

# CIS 7.1.1-7.1.3
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs

# Enable logging failed logins
echo "FAILLOG_ENAB yes" >> /etc/login.defs

# CIS 1.7.1.1-1.7.1.6
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

# CIS 1.1.21
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
# CIS 1.1.22
systemctl disable autofs

# CIS 1.4.1
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
chown root:root /boot/grub2/user.cfg
chmod og-rwx /boot/grub2/user.cfg

# CIS 1.8
yum update --security

%end
