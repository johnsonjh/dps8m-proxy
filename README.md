<!-- Copyright (c) 2025 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025 The DPS8M Development Team -->
<!-- SPDX-License-Identifier: MIT -->
<!-- vim: ft=markdown expandtab : -->
# dps8m-proxy

### Using OpenSSH host keys

If you have existing OpenSSH Ed25519 or RSA host keys that you want
to use with the proxy, you'll need to convert those keys to standard
PEM format. **NB**: these instructions *do not* include specific
instructions for safe handling of keyfile permissions—we assume you
know what you're doing!

1. Make a *copy* the key files you wish to convert.  Note that these
   copies will be *overwritten* in the conversion process.

   ```sh
   cp /etc/ssh/ssh_host_rsa_key ssh_host_rsa_key.tmp
   cp /etc/ssh/ssh_host_ed25519_key ssh_host_ed25519_key.tmp
   ```

2. Convert the key using `ssh-keygen` and rename it appropriately:
   ```sh
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_rsa_key.tmp
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_ed25519_key.tmp
   mv ssh_host_rsa_key.tmp ssh_host_rsa_key.pem
   mv ssh_host_ed25519_key.tmp ssh_host_ed25519_key.pem 
   ```
