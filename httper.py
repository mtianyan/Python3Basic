# -*- coding: utf-8 -*-
__author__ = 'bliss'

from urllib import request as httpreq
from http.client import HTTPSConnection
from flask import json


class Httper(object):
    def get(self, url):
        return httpreq.urlopen(url)

    def post(self, host, url, data, headers=None):
        tmp_data = json.dumps(data)
        tmp_data = tmp_data.encode(encoding='utf-8')
        con = HTTPSConnection(host)
        con.request("POST", url, body=tmp_data, headers=headers)
        r = con.getresponse()
        # res = r.read()
        return r



