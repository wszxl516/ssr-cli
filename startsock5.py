#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement
from shadowsocks import eventloop, tcprelay, udprelay, asyncdns, daemon


class Sock5server:
    def __init__(self, param: dict) -> None:
        super(Sock5server, self).__init__()
        self.param = param

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.param = None

    def start_server(self) -> None:
        config = self.update_param(self.param)
        if not config.get('dns_ipv6', False):
            asyncdns.IPV6_CONNECTION_SUPPORT = False
        try:
            dns_resolver = asyncdns.DNSResolver()
            tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
            udp_server = udprelay.UDPRelay(config, dns_resolver, True)
            loop = eventloop.EventLoop()
            dns_resolver.add_to_loop(loop)
            tcp_server.add_to_loop(loop)
            udp_server.add_to_loop(loop)
            loop.run()
        except Exception as e:
            print(e)

    @staticmethod
    def update_param(param: dict) -> dict:
        config = {
                  'method': 'rc4-md5',
                  'protocol': 'auth_aes128_md5',
                  'protocol_param': '25007:nIPDtG',
                  'obfs': 'tls1.2_ticket_auth',
                  'obfs_param': 'news.microsoft.com/dda8825007/',
                  'local_address': '0.0.0.0',
                  'local_port': 1080,
                  'port_password': None,
                  'additional_ports': {},
                  'additional_ports_only': False,
                  'timeout': 300,
                  'udp_timeout': 120,
                  'udp_cache': 64,
                  'fast_open': False,
                  'workers': 1,
                  'pid-file': 'ssr.pid',
                  'log-file': 'ssr.log',
                  'verbose': True,
                  'connect_verbose_info': 0
        }
        config.update(param)
        return config

    def run(self) -> None:
        self.start_server()

    @staticmethod
    def daemon_start():
        daemon.daemon_start('ssr.pid',
                            'ssr.log')

    @staticmethod
    def daemon_stop():
        daemon.daemon_stop('ssr.pid')


if __name__ == '__main__':
    with Sock5server({})as s:
        s.run()
