#!/usr/bin/env python

# title			    :fake-sshd.py
# description	    :This script is a fake ssh server logging authentication (login/password or public key) requests.
# author		    :Benoit MAUDET
# date			    :20170101
# version		    :0.2
# usage			    :python fake-sshd.py
# notes			    :requires: apt install python-setuptools python-pip python-dev gcc & pip install paramiko python-gssapi
# notes			    :to generate rsa_ssh: ssh-keygen rsa

import socket
import threading
import traceback
import paramiko

bind_port = 22
fake_version = 'SSH-2.0-OpenSSH_3.7.1p2'
host_key = paramiko.RSAKey(filename='rsa_ssh')


class FakeSSHServer(paramiko.ServerInterface):

    def __init__(self, address):
        self.address = address

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        print("%s %s %s" % (self.address, username, password))
        auth_logfile = open("ssh_auth.log", 'a')
        auth_logfile.write("%s %s %s\n" % (self.address, username, password))
        auth_logfile.close()
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print("%s %s %s %s" % (self.address, username, key.get_name(), key.get_base64()))
        auth_logfile = open("ssh_auth.log", 'a')
        auth_logfile.write("%s %s %s %s\n" % (self.address, username, key.get_name(), key.get_base64()))
        auth_logfile.close()
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth,
                                  pixelheight, modes):
        return False


class ThreadedFakeSSHServer:
    def __init__(self):
        self.event = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', bind_port))

    def listen(self):
        self.sock.listen(100)
        while True:
            try:
                client, address = self.sock.accept()
                client.settimeout(60)
                threading.Thread(target=self.listen_to_client, args=(client, address)).start()
            except Exception as e:
                traceback.print_exc()
                continue

    def listen_to_client(self, client, address):
        transport = paramiko.Transport(client)
        try:
            transport.load_server_moduli()
        except:
            transport.close()
            raise
        transport.add_server_key(host_key)
        server = FakeSSHServer(address[0])
        transport.local_version = fake_version
        transport.start_server(server=server)

        # wait for auth
        chan = transport.accept(20)

        if chan is None:
            transport.close()
        else:
            server.event.wait(2)
            if not server.event.is_set():
                transport.close()
            chan.close()
            transport.close()

ThreadedFakeSSHServer().listen()
