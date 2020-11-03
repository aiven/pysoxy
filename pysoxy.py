# -*- coding: utf-8 -*-
"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

# Config
import argparse
# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, activeCount
import requests
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
import json
#
# Configuration
#
parser = argparse.ArgumentParser(description="Process server params")
parser.add_argument("--port", default=1080, help="Port to bind the server to")
parser.add_argument("--host", default="0.0.0.0", help="Interface to bind the server to")
parser.add_argument("--username", default=None, help="Username for user/pass auth")
parser.add_argument("--password", default=None, help="Password for user/pass auth")
parser.add_argument("--authenticator", default=None, help="External authenticator URL")
parser.add_argument("--cafile", default=None, help="External authenticator cert file")
args = parser.parse_args()
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = args.host
LOCAL_PORT = args.port
USERNAME = args.username
PASSWORD = args.password
AUTHENTICATOR_URL = args.authenticator
CA_FILE = args.cafile
# Parameter to bind a socket to a device, using SO_BINDTODEVICE
# Only root can set this option
# If the name is an empty string or None, the interface is chosen when
# a routing decision is made
# OUTGOING_INTERFACE = "eth0"
OUTGOING_INTERFACE = ""

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# '02' USER/PASS AUTHENTICATION REQUIRED
M_USER_AUTH = b'\x02'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'
# IP V6 address
ATYP_IPV6 = b'\x04'


class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def proxy_loop(socket_src, socket_dst):
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            print("Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def request_client(wrapper):
    """ Client request details """
    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False
    # Check VER, CMD and RSV
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False
    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    # IPV6
    # socket.inet_ntoa()
    # elif s5_request[3:4] == ATYP_IPV6:
    #     pass
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    elif s5_request[3:4] == ATYP_IPV6:
        pass
    else:
        return False
    print(dst_addr, dst_port)
    return (dst_addr, dst_port)


def request(wrapper):
    """
        The SOCKS request information is sent by the client as soon as it has
        established a connection to the SOCKS server, and completed the
        authentication negotiations.  The server evaluates the request, and
        returns a reply
    """
    dst = request_client(wrapper)
    # Server Reply
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
    if dst:
        socket_dst = connect_to_dst(dst[0], dst[1])
    if not dst or socket_dst == 0:
        rep = b'\x01'
    else:
        rep = b'\x00'
        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])
    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return
    # start proxy
    if rep == b'\x00':
        proxy_loop(wrapper, socket_dst)
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def subnegotiation_client(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
    """
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    try:
        identification_packet = wrapper.recv(BUFSIZE)
        print(f"first package: {identification_packet}")
    except socket.error:
        error()
        return M_NOTAVAILABLE
    # VER field
    if VER != identification_packet[0:1]:
        return M_NOTAVAILABLE
    # METHODS fields
    nmethods = identification_packet[1]
    methods = identification_packet[2:]
    if len(methods) != nmethods:
        return M_NOTAVAILABLE
    for method in methods:
        if method == ord(M_USER_AUTH):
            return M_USER_AUTH
    return M_NOTAVAILABLE


def subnegotiation(wrapper):
    """
        The client connects to the server, and sends a version
        identifier/method selection message
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message, then follows the steps required
        for the auth method to succeed
    """
    method = subnegotiation_client(wrapper)
    print(f"Using method {method}")
    # Server Method selection message
    #
    # Reply
    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    if method != M_USER_AUTH:
        print(f"Invalid method: {method}")
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error:
        error()
        return False
    failed_auth_reply = b"\x01\x01"
    success_auth_reply = b"\x01\x00"
    try:
        version, = unpack("B", wrapper.recv(1))
        if version != 1:
            wrapper.sendall(failed_auth_reply)
            print("Invalid version byte")
            return False
        user_len, = unpack("B", wrapper.recv(1))
        user = wrapper.recv(int(user_len)).decode()
        pass_len, = unpack("B", wrapper.recv(1))
        password = wrapper.recv(int(pass_len)).decode()
        if user_len != len(user) or pass_len != len(password):
            wrapper.sendall(failed_auth_reply)
            print("Invalid user / pass len")
            return False
        if AUTHENTICATOR_URL is not None:
            payload = {
                "type": "aiven_proxy_authorization_v1",
                "username": user,
                "password": password,
            }
            resp = requests.post(AUTHENTICATOR_URL, json=payload, verify=False if not CA_FILE else CA_FILE)
            if not resp.ok:
                wrapper.sendall(failed_auth_reply)
                return False
            try:
                data = resp.json()
                if "decision" not in data or data["decision"] != "authenticated":
                    wrapper.sendall(failed_auth_reply)
                    return False
            except json.JSONDecodeError:
                wrapper.sendall(failed_auth_reply)
                return False
        elif user != USERNAME or password != PASSWORD:
            print("Invalid user / pass")
            wrapper.sendall(failed_auth_reply)
            return False
    except socket.error:
        error()
        return False
    print("Auth successful")
    wrapper.sendall(success_auth_reply)
    return True


def connection(wrapper):
    """ Function run by a thread """
    if subnegotiation(wrapper):
        request(wrapper)


def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock


def bind_port(sock):
    """
        Bind the socket to address and
        listen for connections made to the socket
    """
    try:
        print('Bind {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(0)
    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(0)
    return sock


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)


def main():
    """ Main function """
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)
        recv_thread = Thread(target=connection, args=(wrapper, ))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()
