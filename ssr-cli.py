#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement
from shadowsocks import eventloop, tcprelay, udprelay, asyncdns, daemon
import json
import fire
import os
import sys
import requests
import base64
from urllib import parse
app_home = os.path.join(os.getenv('HOME'), '.ssr-cli')
ssr_log = os.path.join(os.getenv('HOME'), '.ssr-cli', 'ssr.log')
ssr_pid = os.path.join(os.getenv('HOME'), '.ssr-cli', 'ssr.pid')


class Subscription:
    def __init__(self, sub_url):
        """
        :param sub_url: ssr订阅地址
        """
        self._url = sub_url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def _get_content(self):
        try:
            res = requests.get(self._url)
            if res.status_code != 200:
                return False, res.text
            else:
                return True, res.text
        except requests.exceptions.MissingSchema as error:
            return False, error
        except Exception as error:
            return False, error

    @staticmethod
    def base642url(code):
        return base64.b64decode(code + '===').decode()

    @staticmethod
    def urlsafe_decode(code):
        return base64.urlsafe_b64decode(code + '===').decode()

    @staticmethod
    def get_param(url):
        response = parse.urlparse(url)
        server = response.scheme
        server_port, protocol, method, obfs, password = response.path.split(':')
        base_params = parse.parse_qs(response.query)
        params = {k: Subscription.urlsafe_decode(v[0]) for k, v in base_params.items()
                  if k != 'remarks'}
        params['remarks'] = Subscription.urlsafe_decode(base_params['remarks'][0])
        params['password'] = Subscription.base642url(password[:-1])
        params['server'] = server
        params['server_port'] = server_port
        params['method'] = method
        params['protocol'] = protocol
        params['obfs'] = obfs
        return params

    @staticmethod
    def url2json(urls):
        data = []
        for line in urls.split('\n'):
            if line.strip() == '':
                continue
            pro_type, line = line.split('://')
            ssr_url = Subscription.urlsafe_decode(line)
            node = Subscription.get_param(ssr_url)
            if 'obfsparam' in node:
                node['obfs_param'] = node['obfsparam']
                del node['obfsparam']
            if 'protoparam' in node:
                node['protocol_param'] = node['protoparam']
                del node['protoparam']
            data.append(node)
        return data

    @property
    def json(self):
        ok, content = self._get_content()
        if not ok:
            return {'code': 1,
                    'message': content}
        else:
            urls = Subscription.base642url(content)
            json = Subscription.url2json(urls)
            return {'code': 0,
                    'data': json}


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
                  'pid-file': ssr_pid,
                  'log-file': ssr_log,
                  'verbose': True,
                  'connect_verbose_info': 0
        }
        config.update(param)
        return config

    def run(self) -> None:
        self.start_server()

    @staticmethod
    def daemon_start():
        daemon.daemon_start(ssr_pid,
                            ssr_log)

    @staticmethod
    def daemon_stop():
        if os.path.exists(os.path.join(app_home, 'ssr.pid')):
            daemon.daemon_stop(ssr_pid)
        else:
            Log.warring('socks5 proxy not running!')


class Log:
    @staticmethod
    def info(message: str, end='\n'):
        print('\x1b[32m', message, '\x1b[0m', end=end)

    @staticmethod
    def warring(message: str, end='\n'):
        print('\x1b[33m', message, '\x1b[0m', end=end)

    @staticmethod
    def error(message: str, end='\n'):
        print('\x1b[31m', message, '\x1b[0m', end=end)
        sys.exit(1)


class Cli:
    def __init__(self) -> None:
        self._config_file = os.path.join(app_home, 'config.json')
        if not os.path.exists(app_home):
            os.mkdir(app_home)
        if not os.path.exists(self._config_file) or not os.path.isfile(self._config_file):
            with open(self._config_file, 'w')as fp:
                fp.write('{"sub_url": ""}')
                Log.error('please fill in config file {}!'.format(self._config_file))
        self._config = {}
        self._get_config()

    @staticmethod
    def stop():
        """
        stop current node
        :return:
        """
        Sock5server.daemon_stop()

    @staticmethod
    def status():
        """
        ssr status
        """
        if os.path.exists(os.path.join(app_home, 'ssr.pid')):
            with open(os.path.join(app_home, 'ssr.pid'))as fp:
                pid = fp.read().strip()
            if os.path.exists(os.path.join('/proc', pid)):
                Log.info('Running PID: {}'.format(pid))
            else:
                Log.warring('Not Running or not be monitored with ssr-cli!')
        else:
            Log.warring('Not Running or not be monitored with ssr-cli!')

    def _get_config(self) -> None:
        with open(self._config_file, 'r')as fp:
            self._config = json.load(fp)

    def _save_config(self) -> None:
        with open(self._config_file, 'w')as fp:
            json.dump(self._config, fp)

    def _get_by_name(self, name: str) -> str or None:
        if name in self._config:
            return self._config[name]
        else:
            return None

    def update(self) -> None:
        """
        update subscription
        :return: None
        """
        sub_url = self._get_by_name('sub_url')
        if sub_url is None:
            Log.error('no sub_url in {}!'.format(self._config_file))
        with Subscription(sub_url) as sub:
            sub_data = sub.json
        if sub_data.get('code', 1) != 0:
            Log.error('get subscription failed: {}!'.format(sub_data.get('message')))
        self._config['sub_nodes'] = sub_data.get('data')
        self._save_config()
        Log.info("update success!")

    def list(self) -> None:
        """
        list all ssr node
        :return:
        """
        sub_nodes = self._get_by_name('sub_nodes')
        if sub_nodes is None:
            Log.error('no useful node!')
        else:
            for num, node in enumerate(sub_nodes):
                Log.warring(num, end=' ')
                print(node.get('remarks'))

    def switch(self, node: int) -> None:
        """
        switch to node
        :param node: node number
        :return:
        """
        sub_nodes = self._get_by_name('sub_nodes')
        if sub_nodes and sub_nodes.__len__() + 1 < node:
            Log.error('no that node inside!')
        Log.info('switch to {} success!'.format(sub_nodes[node].get('remarks')))
        if os.path.exists('ssr.pid'):
            Sock5server.daemon_stop()
        node_dict = sub_nodes[node]
        node_dict['password'] = node_dict['password'].encode()
        node_dict['server_port'] = int(node_dict['server_port'])
        Sock5server.daemon_start()
        with Sock5server(node_dict)as s:
            s.run()


if __name__ == '__main__':
    fire.Fire(Cli())
