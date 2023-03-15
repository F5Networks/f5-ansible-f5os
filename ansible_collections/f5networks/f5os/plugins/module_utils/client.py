# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.f5networks.f5os.plugins.module_utils.constants import (
    BASE_HEADERS, ROOT
)

from ansible_collections.f5networks.f5os.plugins.module_utils.teem import TeemClient


def header(method):
    def wrap(self, *args, **kwargs):
        args = list(args)
        if 'scope' in kwargs:
            args[0] = kwargs['scope'] + args[0]
            kwargs.pop('scope')
        else:
            args[0] = ROOT + args[0]
        if 'headers' not in kwargs:
            kwargs['headers'] = BASE_HEADERS
            return method(self, *args, **kwargs)
        else:
            kwargs['headers'].update(BASE_HEADERS)
            return method(self, *args, **kwargs)
    return wrap


class F5Client:
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        self.plugin = kwargs.get('client', None)

    @header
    def delete(self, url, **kwargs):
        return self.plugin.send_request(path=url, method='DELETE', **kwargs)

    @header
    def get(self, url, **kwargs):
        return self.plugin.send_request(path=url, method='GET', **kwargs)

    @header
    def patch(self, url, data=None, **kwargs):
        return self.plugin.send_request(path=url, method='PATCH', payload=data, **kwargs)

    @header
    def post(self, url, data=None, **kwargs):
        return self.plugin.send_request(path=url, method='POST', payload=data, **kwargs)

    @header
    def put(self, url, data=None, **kwargs):
        return self.plugin.send_request(path=url, method='PUT', payload=data, **kwargs)

    @property
    def platform(self):
        return self.plugin.get_platform_type()

    @property
    def ansible_version(self):
        return self.module.ansible_version

    @property
    def module_name(self):
        return self.module._name


def send_teem(client, start_time):
    """ Sends Teem Data if allowed."""
    if client.plugin.telemetry():
        teem = TeemClient(client, start_time)
        teem.send()
    else:
        return False
