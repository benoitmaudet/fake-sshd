#!/usr/bin/env python

# title			:fake-sshd.py
# description	:This script is a fake ssh server logging authentication (login/password) requests.
# author		:Benoit MAUDET
# date			:20170101
# version		:0.1
# usage			:python fake-sshd.py
# notes			:requires: apt install python-setuptools python-pip python-dev gcc & pip install paramiko python-gssapi
# notes			:to generate rsa_ssh: ssh-keygen rsa

import socket
import threading
import traceback
import paramiko

paramiko.util.log_to_file('ssh_server.log')
host_key = paramiko.RSAKey(filename='rsa_ssh')
fake_version = 'SSH-2.0-OpenSSH_3.7.1p2'

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        print "\t%s %s" % (username, password)
        auth_logFile.write("\t%s %s\n" % (username, password))
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print "\t%s %s %s" % (username, key.get_name(), key.get_base64())
        auth_logFile.write("\t%s %s %s\n" % (username, key.get_name(), key.get_base64()))
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth,
                                  pixelheight, modes):
        return False


while True:
    auth_logFile = open("ssh_auth.log", 'a')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 22))
    except Exception as e:
        traceback.print_exc()
        auth_logFile.close()
        continue

    try:
        sock.listen(100)
        client, addr = sock.accept()
        print("%s" % addr[0])
        auth_logFile.write("%s\n" % addr[0])
    except Exception as e:
        traceback.print_exc()
        auth_logFile.close()
        continue

    try:
        transport = paramiko.Transport(client)
        transport.set_gss_host(socket.getfqdn(""))
        try:
            transport.load_server_moduli()
        except:
            raise
        transport.add_server_key(host_key)
        server = FakeSSHServer()
        try:
            transport.local_version = fake_version
            transport.start_server(server=server)
        except paramiko.SSHException:
            auth_logFile.close()
            continue
        # wait for auth
        chan = transport.accept(20)

        auth_logFile.close()

        if chan is None:
            transport.close()
            continue
        server.event.wait(2)
        if not server.event.is_set():
            transport.close()
            continue
        chan.close()
        transport.close()

    except Exception as e:
        traceback.print_exc()
        try:
            transport.close()
        except:
            pass
