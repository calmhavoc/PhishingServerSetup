from cmd import Cmd
# import configparser
import os, subprocess, random, string
from urllib.request import urlopen
import templates as template

# PS1='\e[37;1m\u@\e[35m\W\e[0m\$ '
# LS_COLORS='rs=0:di=1;35:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:'
# export LS_COLORS

# Default error handling to keep from getting bounced on error
def catch_exception(f):
    import functools
    @functools.wraps(f)
    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            print('Caught an exception in', f.__name__)
            print(str(e))
    return func


class Config(object):
    def __init__(self):
        self.hostname = "us"
        self.domain = ""
        self.fqdn = ""
        self.externalIP = ""
        self.allowedIPs = ""
        self.relayIP = ""
        self.rootMailUser = ""
        self.mailcheck = ""
        self.mailarchive = ""
        self.weburl = ""

class Begin(Cmd):
    '''starting out'''

    global config
    config = Config()

    def do_greet(self,line):
        print("Hello and Welcome! ")

    def do_EOF(self,line):
        print("""FQDN: {}\nPasswords\n{}\n{}""").format(config.fqdn,config.mailcheck,config.mailarchive)
        return True

    def do_1_gather_requirements(self, line):
        ''' Ran first. Gathers required info such as hostname, IP addresses, usernames, etc. 
        Maybe other things'''
        # config = configparser.ConfigParser()
        # config.read('config.ini')
        config.hostname = input("Enter hostname (mail): ")
        config.domain = input("Enter domain (example.org): ")
        config.fqdn = input("Enter your fqdn (eg mail.example.org): ")
        config.allowedIPs = input("Enter comma separated IPs that can ssh to this host: ")
        # handle ranges also
        config.relayIP =  input("Enter relay IP for mail if any: ")
        config.rootMailName = "root" #input("Who will recieve mail for root")
        config.mailcheck = ""
        config.mailarchive = ""


    # def do_create_backups(self,line):
    #     """ create backup of all files that we modify before touching them """
    #     # /etc/opendkim.com
    #     # /etc/opendkim/TrustedHosts
    #     # /etc/default/opendkim
    #     # 
    #     pass
        
    # def do_read_config(self,line):
    #     """ Reads a config file and updateds variables with the contents
    #     hostname
    #     domain
    #     fqdn
    #     allowSSHfrom
    #     relayIPs
    #     rootMailName
    #     mailAdminName
    #     mailArchiveName

    #     """

    @catch_exception
    def do_2_init(self,line):
        global config
        if os.geteuid() != 0:
            print("Must be root")
            do_greet
        fqdn = config.fqdn
        hostname = config.hostname
        domain = config.domain
        hostname = fqdn.split('.')[1]
        domain = '.'.join(fqdn.split('.')[-2:])
        # apt update/upgrade should be ran prior to script idk. Run this first to update and ensure basic tools are installed 
        # apt install basics, remove conflicting packages like sendmail, set hostname
        subprocess.call("apt-get update", shell=True)
        subprocess.call("apt-get install -y dnsutils curl debconf-utils", shell=True)
        subprocess.call("echo postfix postfix/mailname string {} | debconf-set-selections; echo postfix postfix/main_mailer_type string 'Internet Site' | debconf-set-selections ;export DEBIAN_FRONTEND=noninteractive; apt-get install -y procmail".format(fqdn), shell=True)
        subprocess.call("echo postfix postfix/mailname string {} | debconf-set-selections".format(fqdn), shell=True)
        subprocess.call("echo postfix postfix/main_mailer_type string 'Internet Site' | debconf-set-selections", shell=True)
        subprocess.call("export DEBIAN_FRONTEND=noninteractive; apt-get install -y procmail", shell=True)
        
        # apt-get remove -qq -y exim4 exim4-base exim4-config exim4-daemon-light > /dev/null 2>&1
        # rm -r /var/log/exim4/ > /dev/null 2>&1

        # update-rc.d nfs-common disable > /dev/null 2>&1
        # update-rc.d rpcbind disable > /dev/null 2>&1

        with open('/etc/hosts', 'w+') as f:
            f.write('127.0.1.1\t{}\t{}\n'.format(hostname,domain))
            f.write('127.0.0.1\tlocalhost\t{}\n'.format(domain))
        with open('/etc/hostname','w+') as f:
            f.write('{}'.format(hostname))

    # def do_set_firewall(self,line):
    #     ''' A bunch of preconfigured options for setting the firewall based on what we've configured'''
    #     pass
    #     # return True

    # def do_baseline_system(self, line):
    #     ''' Makes a backup of config files that we will be touching. looks at current packages for uninstalling others. services'''
    #     # /etc/hosts
    #     # /etc/hostname
    #     # /etc/apache2/*
    #     # /etc/dovecot/*
    #     # /etc/logrotate.d/
    #     # /etc/opendkim/*
    #     # /etc/pam.d/imap
    #     # /etc/postfix/*
    #     # /var/www/html/.htaccess
    #     # rm -rf /etc/letsencrypt/*
    #     pass

    def do_3_install_ssl(self, line):
        # print("""External IP Address: {}\nDomain: {}\nFQDN: {}""").format(config.externalIP,config.domain,config.fqdn)
        ''' Installs letsencrypt for mail and web '''
        if not os.path.isdir('/etc/letsencrypt'):
            # install it
            self.run_command('apt-get update')
            self.run_command('service apache2 stop')
            self.run_command('apt-get install software-properties-common -y')
            self.run_command('apt-get install certbot -y')

        else:
            print("Let's Encrypt is already installed\n")
        # os.chdir('/opt/letsencrypt')
        
        self.run_command('service apache2 stop')
        certbot = 'certbot certonly --standalone --register-unsafely-without-email --agree-tos -d {}'
        subprocess.call(certbot.format(config.domain), shell=True)
        # subprocess.call(certbot.format(config.fqdn), shell=True)

        #pass



    def do_4_install_mailserver(self, line):
        ''' installs postfix and dovecot '''
        ### needs to read from template file and replace variables with ours

        self.run_command('adduser mailarchive --quiet --disabled-password --shell /usr/sbin/nologin --gecos ""')
        self.run_command('adduser mailcheck --quiet --disabled-password --shell /usr/sbin/nologin --gecos ""')
        mailArchivePassword = self.gen_password(32)
        mailCheckPassword = self.gen_password(32)
        self.run_command('echo "mailarchive:{}" | chpasswd'.format(mailArchivePassword))
        self.run_command('echo "mailcheck:{}" | chpasswd'.format(mailCheckPassword))
        config.mailarchive = "mailarchive:{}".format(mailArchivePassword)
        config.mailcheck = "mailcheck:{}".format(mailCheckPassword)

        print('Installing Dovecot\n')
        self.run_command('apt-get install -y dovecot-common dovecot-imapd dovecot-lmtpd')
        print('Installing Postfix\n')
        self.run_command('apt-get install -y postfix postgrey postfix-policyd-spf-python')
        print('Installing OpenDKIM and OpenDMARC\n')
        self.run_command('apt-get install -y opendkim opendkim-tools opendmarc')
        print('Installing mailutils')
        self.run_command('apt-get install -y mailutils')

        # POSTFIX
        self.write_file('/etc/postfix/main.cf',template.main_cf.format(config.domain,config.relayIP))
        self.append_file('/etc/postfix/esmtp_access',template.esmtp_access)
        self.append_file('/etc/postfix/master.cf',template.master_cf)

        # OPENDKIM
        if not os.path.exists('/etc/opendkim/keys/{}'.format(config.domain)):
            os.makedirs('/etc/opendkim/keys/{}'.format(config.domain))
        self.write_file('/etc/opendkim.conf',template.opendkim_conf)
        self.write_file('/etc/opendkim/TrustedHosts',template.TrustedHosts.format(config.domain,config.relayIP))
        self.run_command('opendkim-genkey --bits=1024 --selector=mail --domain={0} --directory=/etc/opendkim/keys/{0}'.format(config.domain))
        self.run_command('echo SOCKET="inet:12301" >> /etc/default/opendkim')
        self.run_command('chown -R opendkim:opendkim /etc/opendkim')

        # DMARC
        self.write_file('/etc/opendmarc.conf',template.opendmarc_conf.format(config.domain))
        if not os.path.exists('/etc/opendmarc'):
            self.run_command('mkdir /etc/opendmarc')
        self.run_command('echo "localhost" > /etc/opendmarc/ignore.hosts')
        self.run_command('chown -R opendmarc:opendmarc /etc/opendmarc')
        self.run_command('echo SOCKET="inet:54321" >> /etc/default/opendmarc')

        # Dovecot
        self.write_file('/etc/dovecot/dovecot.conf',template.dovecot_conf.format(config.domain))
        self.write_file('/etc/logrotate.d/dovecot',template.logrotated_dovecot)

        # PAM/IMAP
        self.write_file('/etc/pam.d/imap',template.pamd_imap)
        

        self.run_command('service postfix restart')
        self.run_command('service dovecot restart')

    # def do_install_webserver(self,line):
    #     ''' Not yet implemented '''

    #     # self.run_command('mkdir /var/www/html/placeholder')
    #     # self.run_command('mkdir /var/www/html/archive')
    #     # Apache
    #     commands = ["a2enmod rewrite","service apache2 stop", "a2enmod ssl", "a2enmod headers", "a2enmod https"]
    #     path = '/etc/apache2/sites-enabled'
    #     commands2 = ["a2dissite {0}/000-default","a2dissite {0}default-ssl", "a2dissite {0}000-default.conf", "a2dissite {0}default-ssl.conf"]

    #     for command in commands: 
    #         self.run_command(command)

    #     for command in commands2:
    #         self.run_command(command.format(path))

            
        # self.write_file('/etc/postfix/main.cf',template.main_cf.format(config.domain,config.relayIP))
        # self.write_file('/etc/postfix/main.cf',template.main_cf.format(config.domain,config.relayIP))
        # self.write_file('/etc/postfix/main.cf',template.main_cf.format(config.domain,config.relayIP))
        # self.write_file('/etc/postfix/main.cf',template.main_cf.format(config.domain,config.relayIP))        # Create logic to clone website in /var/www/html







    # def do_remove_all_packages(self,line):
    #     a = input("This will remove all packages that this script has added but could have unintended consequences. Continue? ")
    #     if a.lower() == "y":
    #         run_command("apt-get purge apache2 python-certbot-apache procmail dovecot-common dovecot-imapd dovecot-lmtpd postfix postgrey postfix-policyd-spf-python opendkim opendkim-tools opendmarc mailutils")
    #         run_command("apt-get autoremove apache2 python-certbot-apache procmail dovecot-common dovecot-imapd dovecot-lmtpd postfix postgrey postfix-policyd-spf-python opendkim opendkim-tools opendmarc mailutils")

    # def do_set_https_web(self, line):
    #     ''' sets up webserver for ssl only'''
    #     pass

    # def do_httpsc2doneright(self, line):
    #     ''' configures https done right for cobaltstrike '''
    #     pass


    def do_print_DNS(self, line):
        ''' Prints the DNS records that should be present for the domain '''
        serverExtIP = urlopen("http://ifconfig.me").read().decode()
        with open('/etc/opendkim/keys/{0}/mail.txt'.format(config.domain)) as f:
            txt = f.read()

        dkim = txt.split('"')[1]+txt.split('"')[3]
        
        print(template.dns1.format(config.domain,serverExtIP,dkim))

    # def do_change_domain(self, line):
    #     ''' Allows us to modify this server to work with a different domain '''
    #     pass

    # def do_install_webmail(self, line):
    #     ''' sets up an instance for us to use the mail server, check mail, interact,respond,etc '''
    #     pass

    # def disable_ipv6(self,line):
    #     # cat <<-EOF >> /etc/sysctl.conf
    #     # net.ipv6.conf.all.disable_ipv6 = 1
    #     # net.ipv6.conf.default.disable_ipv6 = 1
    #     # net.ipv6.conf.lo.disable_ipv6 = 1
    #     # net.ipv6.conf.eth0.disable_ipv6 = 1
    #     # net.ipv6.conf.eth1.disable_ipv6 = 1
    #     # net.ipv6.conf.ppp0.disable_ipv6 = 1
    #     # net.ipv6.conf.tun0.disable_ipv6 = 1
    #     # EOF
    #     # sysctl -p > /dev/null 2>&1

    #     pass

    def run_command(self,command):
        subprocess.call(command, shell=True)

    def write_file(self, file, lines):
        with open(file,'w+') as f:
            f.write(lines)

    def append_file(self, file, lines):
        with open(file,'a+') as f:
            f.write(lines)

    def gen_password(self,length=32):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

    
    def do_exit(self,*args):
        return True


if __name__ == '__main__':
    Begin().cmdloop()


# config = configparser.ConfigParser()
# config.read('config.ini')

# secret_key = config['DEFAULT']['SECRET_KEY'] # 'secret-key-of-myapp'
# ci_hook_url = config['CI']['HOOK_URL'] # 'web-hooking-url-from-ci-service'
