# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from unittest import TestCase
from ansible_collections.f5networks.f5os.plugins.module_utils.common import (
    fq_name, flatten_boolean, merge_two_dicts
)


class TestFunctions(TestCase):
    def test_fq_name(self):
        res1 = fq_name('Foo', '100',)
        assert res1 == '/Foo/100'

        res2 = fq_name('Foo', '1.1')
        assert res2 == '/Foo/1.1'

        res3 = fq_name('Foo', '100', 'Bar')
        assert res3 == '/Foo/Bar/100'

        res4 = fq_name('Foo', '/Baz/Resource', 'Bar')
        assert res4 == '/Baz/Bar/Resource'

        res5 = fq_name('Foo', 'Resource', 'Bar')
        assert res5 == '/Foo/Bar/Resource'

        res6 = fq_name('Foo', None)
        assert res6 is None

    def test_flatten_boolean(self):
        true = 'enabled'
        false = 'disabled'

        res1 = flatten_boolean(true)
        res2 = flatten_boolean(false)
        res3 = flatten_boolean(None)

        assert res1 == 'yes'
        assert res2 == 'no'
        assert res3 is None

    def test_merge_two_dics(self):
        first = dict(foo=1, bar=2)
        second = dict(baz=3)
        result = merge_two_dicts(first, second)

        assert result == {'foo': 1, 'bar': 2, 'baz': 3}
