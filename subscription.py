#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import base64
from urllib import parse
import pprint


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


def test():
    with Subscription('...') as sub:
        pprint.pprint(sub.json)


if __name__ == '__main__':
    test()
