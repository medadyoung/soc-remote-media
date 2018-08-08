# Virtual Media Server

This is a Virtual Media Server program to receive command from IT's PC to launch nbd-client(on BMC) which will connect to nbd-server in IT's PC.

1) Please provide key pairs for TLS.
    * /etc/remote-media/cert.pem
    * /etc/remote-media/privatekey.pem
2) Please provide the passphase for privatekey.pem.
    * In /etc/remote-media/rms.cfg
    * Example:
    * PrivateKeyPassphrase: cs20nuvoton
3) Virtual Media Server listen on port 8080.
    * You could start Virtual Media Server on the other port via argv
    * ./Remote-Media-Server port
4) NBD Client should connect to NBD server with TLS enabled via -x option
    * nbd-client 192.168.1.129 443 /dev/nbd1 -x -b 512 -N Poleg
5) LDAP auth is disabled by default.
    * If you want to enable it, please define LDAP_AUTH
