# 0 = primary_domain, 1 = relay_ip
main_cf = """smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
readme_directory = no
smtpd_tls_cert_file=/etc/letsencrypt/live/{0}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/{0}/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_session_cache_database = btree:\${{data_directory}}/smtpd_scache
smtp_tls_session_cache_database = btree:\${{data_directory}}/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = {0}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = {0}
mydestination = {0}, localhost.com, , localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 {1}
mailbox_command = procmail -a "\$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:12301,inet:localhost:54321
non_smtpd_milters = inet:12301,inet:localhost:54321
disable_vrfy_command = yes
smtp_tls_note_starttls_offer = yes
always_bcc = mailarchive@{0}
smtpd_discard_ehlo_keyword_address_maps = cidr:/etc/postfix/esmtp_access
notify_classes = bounce, delay, policy, protocol, resource, software
bounce_notice_recipient = mailcheck
delay_notice_recipient = mailcheck
error_notice_recipient = mailcheck"""



esmtp_access = """# Allow DSN requests from local subnet only
192.168.0.0/16  silent-discard
172.16.0.0/16   silent-discard
0.0.0.0/0   silent-discard, dsn
::/0        silent-discard, dsn"""

master_cf = """submission inet n       -       -       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_wrappermode=no
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination
  -o smtpd_sender_restrictions=reject_unknown_sender_domain
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth"""
    
opendkim_conf = """domain                              *
AutoRestart                     Yes
AutoRestartRate             10/1h
Umask                                   0002
Syslog                              Yes
SyslogSuccess                   Yes
LogWhy                              Yes
Canonicalization            relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts                   refile:/etc/opendkim/TrustedHosts
KeyFile                             /etc/opendkim/keys/{0}/mail.private
Selector                            mail
Mode                                    sv
PidFile                             /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                              opendkim:opendkim
Socket                              inet:12301@localhost
"""

# 0 = primary_domain, 1 = relay_ip
TrustedHosts = """127.0.0.1
localhost
{0}
{1}"""

# 0 = primary_domain
opendmarc_conf = """AuthservID {0}
PidFile /var/run/opendmarc/opendmarc.pid
RejectFailures false
Syslog true
TrustedAuthservIDs {0}
Socket  inet:54321@localhost
UMask 0002
UserID opendmarc:opendmarc
IgnoreHosts /etc/opendmarc/ignore.hosts
HistoryFile /var/run/opendmarc/opendmarc.dat"""

# 0 = primary_domain
dovecot_conf = """log_path = /var/log/dovecot.log
auth_verbose=yes
auth_debug=yes
auth_debug_passwords=yes
mail_debug=yes
verbose_ssl=yes
disable_plaintext_auth = no
mail_privileged_group = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u
userdb {
  driver = passwd
}
passdb {
  args = %s
  driver = pam
}
protocols = " imap"
protocol imap {
  mail_plugins = " autocreate"
}
plugin {
  autocreate = Trash
  autocreate2 = Sent
  autosubscribe = Trash
  autosubscribe2 = Sent
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}
ssl=required
ssl_cert = </etc/letsencrypt/live/{0}/fullchain.pem
ssl_key = </etc/letsencrypt/live/{0}/privkey.pem"""



pamd_imap = """#%PAM-1.0
auth    required        pam_unix.so nullok
account required        pam_unix.so"""


logrotated_dovecot = """# dovecot SIGUSR1: Re-opens the log files.
/var/log/dovecot*.log {
  missingok
  notifempty
  delaycompress
  sharedscripts
  postrotate
    /bin/kill -USR1 `cat /var/run/dovecot/master.pid 2>/dev/null` 2> /dev/null || true
  endscript
}"""
    

apache2_sites_000 = """<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    <Directory "/var/www/html">
        AllowOverride All
    </Directory>
    ErrorLog \${{APACHE_LOG_DIR}}/error.log
    CustomLog \${{APACHE_LOG_DIR}}/access.log combined
</VirtualHost>"""

# 0 = webaddr eg www.example.org
apache2_ssl_sites = """<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        Protocols h2 http/1.1
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog \${{APACHE_LOG_DIR}}/error.log
        CustomLog \${{APACHE_LOG_DIR}}/access.log combined
        SSLEngine on
        SSLProtocol +TLSv1.1 +TLSv1.2 -SSLv2 -SSLv3
        SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
        SSLCertificateFile /etc/letsencrypt/live/{0}/cert.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/{0}/privkey.pem
        SSLCertificateChainFile /etc/letsencrypt/live/{0}/chain.pem
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
            SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
            SSLOptions +StdEnvVars
        </Directory>
    </VirtualHost>
</IfModule>"""


htaccess = """<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{{HTTPS}} !=on
RewriteRule ^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [L,R=301]
</IfModule> """


# 0 = domain, 1 = servers IP address,2 = dkimrecord
dns1 = """Record Type: A
Host: @
Value: {1}
TTL: 5 min

Record Type: TXT
Host: @
Value: v=spf1 ip4:{1} -all
TTL: 5 min

Record Type: TXT
Host: mail._domainkey
Value: {2}
TTL: 5 min

Record Type: TXT
Host: ._dmarc
Value: v=DMARC1; p=reject
TTL: 5 min

Record Type: MX
Host: @
Value: {0}
Priority: 10
TTL: 5 min
"""

# dns2 = """Record Type: A
# Host: ${prefix}
# Value: ${extip}
# TTL: 5 min

# Record Type: A
# Host: ${namehost}
# Value: ${extip}
# TTL: 5 min

# Record Type: TXT
# Host: ${prefix}
# Value: v=spf1 ip4:${extip} -all
# TTL: 5 min

# Record Type: TXT
# Host: mail._domainkey.${prefix}
# Value: ${dkimrecord}
# TTL: 5 min

# Record Type: TXT
# Host: ._dmarc.${prefix}
# Value: v=DMARC1; p=reject
# TTL: 5 min

# Record Type: MX
# Host: ${prefix}
# Value: ${domain}
# Priority: 10
# TTL: 5 min
# """