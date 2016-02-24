# pam_tarpit
'tarpit' module for pam to piss off and slow down crackers

# Debian Packages Required
`apt-get install build-essential libpam-dev iptables-dev


# Usage
1. Compile the module
2. Add the module to your system (OS X /usr/lib/pam/, Linux /lib/security)
3. Add the module to your pam.d for something (say SSHD)
4. Reap the benefits!

# PAM.D example:
* The arguments are users to tarpit on

eg, to tarpit root, daemon and nobody users:

` auth       sufficient     pam_tarpit.so root daemon nobody`
