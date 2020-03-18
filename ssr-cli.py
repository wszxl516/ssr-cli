#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subscription
import startsock5
import json
import fire
import os
import sys


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
        self._config_file = 'config.json'
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
        startsock5.Sock5server.daemon_stop()

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
            Log.exit('no sub_url in {}!'.format(self._config_file))
        with subscription.Subscription(sub_url) as sub:
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
            startsock5.Sock5server.daemon_stop()
        node_dict = sub_nodes[node]
        node_dict['password'] = node_dict['password'].encode()
        node_dict['server_port'] = int(node_dict['server_port'])
        startsock5.Sock5server.daemon_start()
        with startsock5.Sock5server(node_dict)as s:
            s.run()


if __name__ == '__main__':
    fire.Fire(Cli())
