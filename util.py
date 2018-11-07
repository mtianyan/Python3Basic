# -*- coding:utf-8 -*-
import datetime
import hmac
import os
import base64
from hashlib import sha1 as sha
import random
import re
import time
from flask import request
from advancer.models.base import db

__author__ = 'bliss'

OSS_HOST_LIST = ["aliyun-inc.com", "aliyuncs.com", "alibaba.net", "s3.amazonaws.com"]

SELF_DEFINE_HEADER_PREFIX = "x-oss-"
# if "AWS" == PROVIDER:
#     SELF_DEFINE_HEADER_PREFIX = "x-amz-"

DEBUG = False


def get_content_type_by_filename(file_name):
    mime_map = dict()
    mime_map["js"] = "application/javascript"
    mime_map["xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    mime_map["xltx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.template"
    mime_map["potx"] = "application/vnd.openxmlformats-officedocument.presentationml.template"
    mime_map["ppsx"] = "application/vnd.openxmlformats-officedocument.presentationml.slideshow"
    mime_map["pptx"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    mime_map["sldx"] = "application/vnd.openxmlformats-officedocument.presentationml.slide"
    mime_map["docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    mime_map["dotx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.template"
    mime_map["xlam"] = "application/vnd.ms-excel.addin.macroEnabled.12"
    mime_map["xlsb"] = "application/vnd.ms-excel.sheet.binary.macroEnabled.12"
    mime_map["apk"] = "application/vnd.android.package-archive"
    try:
        name = os.path.basename(file_name)
        suffix = name.split('.')[-1]
        suffix = '.'+ str(suffix)
        if suffix in mime_map.keys():
            mime_type = mime_map[suffix]
        else:
            from .mime import types_map
            mime_type = types_map[suffix]
    except Exception as e:
        mime_type = 'application/octet-stream'
    if not mime_type:
        mime_type = 'application/octet-stream'
    return mime_type


def get_resource(params=None):
    if not params:
        return ""
    tmp_headers = {}
    for k, v in params.items():
        tmp_k = k.lower().strip()
        tmp_headers[tmp_k] = v
    override_response_list = ['response-content-type', 'response-content-language',
                              'response-cache-control', 'logging', 'response-content-encoding',
                              'acl', 'uploadId', 'uploads', 'partNumber', 'group', 'link',
                              'delete', 'website', 'location', 'objectInfo',
                              'response-expires', 'response-content-disposition', 'cors', 'lifecycle',
                              'restore', 'qos', 'referer', 'append', 'position']
    override_response_list.sort()
    resource = ""
    separator = "?"
    for i in override_response_list:
        if tmp_headers.get(i.lower()):
            resource += separator
            resource += i
            tmp_key = str(tmp_headers[i.lower()])
            if len(tmp_key) != 0:
                resource += "="
                resource += tmp_key
            separator = '&'
    return resource


def is_oss_host(host, is_oss_host=False):
    if is_oss_host:
        return True
    for i in OSS_HOST_LIST:
        if host.find(i) != -1:
            return True
    return False


def check_bucket_valid(bucket):
    alphabeta = "abcdefghijklmnopqrstuvwxyz0123456789-"
    if len(bucket) < 3 or len(bucket) > 63:
        return False
    if bucket[-1] == "-" or bucket[-1] == "_":
        return False
    if not ((bucket[0] >= 'a' and bucket[0] <= 'z') or (bucket[0] >= '0' and bucket[0] <= '9')):
        return False
    for i in bucket:
        if not i in alphabeta:
            return False
    return True


def is_ip(s):
    try:
        tmp_list = s.split(':')
        s = tmp_list[0]
        if s == 'localhost':
            return True
        tmp_list = s.split('.')
        if len(tmp_list) != 4:
            return False
        else:
            for i in tmp_list:
                if int(i) < 0 or int(i) > 255:
                    return False
    except:
        return False
    return True


def _format_header(headers=None):
    """
    format the headers that self define
    convert the self define headers to lower.
    """
    if not headers:
        headers = {}
    tmp_headers = {}
    for k in headers.keys():
        # if isinstance(headers[k], unicode):
        #     headers[k] = convert_utf8(headers[k])

        if k.lower().startswith(SELF_DEFINE_HEADER_PREFIX):
            k_lower = k.lower().strip()
            tmp_headers[k_lower] = headers[k]
        else:
            tmp_headers[k.strip()] = headers[k]
    return tmp_headers


def get_assign(secret_access_key, method, headers=None, resource="/", result=None, debug=DEBUG):
    """
    Create the authorization for OSS based on header input.
    You should put it into "Authorization" parameter of header.
    """
    if not headers:
        headers = {}
    if not result:
        result = []
    content_md5 = ""
    content_type = ""
    date = ""
    canonicalized_oss_headers = ""
    content_md5 = safe_get_element('Content-MD5', headers)
    content_type = safe_get_element('Content-Type', headers)
    date = safe_get_element('Date', headers)
    canonicalized_resource = resource
    tmp_headers = _format_header(headers)
    if len(tmp_headers) > 0:
        x_header_list = tmp_headers.keys()
        x_header_list = sorted(x_header_list)
        for k in x_header_list:
            if k.startswith(SELF_DEFINE_HEADER_PREFIX):
                canonicalized_oss_headers += "%s:%s\n" % (k, tmp_headers[k])

    string_to_sign = method + "\n" + content_md5.strip() + "\n" + content_type + "\n" + \
                    date + "\n" + canonicalized_oss_headers + canonicalized_resource
    result.append(string_to_sign)
    h = hmac.new(secret_access_key.encode('utf-8'),
                 string_to_sign.encode('utf-8'), sha)
    sign_result = base64.encodebytes(h.digest()).strip()
    # OSS_LOGGER_SET.debug("sign result:%s" % sign_result)
    return str(sign_result, 'utf-8')


def safe_get_element(name, container):
    for k, v in container.items():
        if k.strip().lower() == name.strip().lower():
            return v
    return ""

BUFFER_SIZE = 10*1024*1024


def get_md5():
    import hashlib
    hashs = hashlib.md5()
    return hashs


def get_fp_md5(fd):
    m = get_md5()
    while True:
        d = fd.read(BUFFER_SIZE)
        if not d:
            break
        m.update(d.encode('utf-8'))
    md5string = m.hexdigest()
    base64md5 = base64.encodestring(m.digest()).strip()
    return md5string, base64md5


def get_timestamp_with_random():
    timestamp = int(time.time()*1000)
    return str(timestamp) + str(random.randint(100, 999))


def file_extension(name):
    extension = name.rsplit('.', 1)[1]
    return extension


def year_month_day():
    time_str = datetime.datetime.now().strftime('%Y-%m-%d')
    return time_str


def is_today(date):
    today = datetime.datetime.today()
    delta = today-date
    if delta.days != 0:
        return False
    else:
        return True


def get_today_string():
    today = datetime.date.today().strftime('%Y-%m-%d')
    return today


def convert_paginate(page, per_page):
    start = (page-1) * per_page
    stop = start+per_page
    return start, stop


def validate_int_arguments(value):
    if isinstance(value, int) and value != 0:
        return True
    else:
        return False


def validate_date_arguments(value):
    match = re.match(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}$', value)
    if match:
        return match.group()
    return False


def parse_page_args(request_json):
    if request_json is None:
        if 'page' in request.args:
            page = int(request.args.get('page'))
        else:
            page = 1
        if 'per_page' in request.args:
            per_page = int(request.args.get('per_page'))
        else:
            per_page = 20
    else:
        if 'page' in request_json.keys():
            page = request_json['page']
        else:
            if 'page' in request.args:
                page = int(request.args.get('page'))
            else:
                page = 1
        if 'per_page' in request_json.keys():
            per_page = request_json['per_page']
        else:
            if 'per_page' in request.args:
                per_page = int(request.args.get('per_page'))
            else:
                per_page = 20
    return page, per_page


# 根据图片 ID 获取阿里云 OSS 图片地址
def get_oss_pic_path_by_pic_id(pid, bucket):
    picture = db.session.query(Picture).filter(Picture.id == pid) \
        .first()
    if picture:
        if not picture.path:
            return None
        if picture.path.startswith('http://'):
            return picture.path
        else:
            length = len(picture.path)
            path = picture.path
            object_key = path[17:length]
            full_oss_url = 'http://' + bucket + '.oss-cn-qingdao.aliyuncs.com' + '/' + object_key
            return full_oss_url
    else:
        return None


# 根据图片 ID 获取阿里云 IMG 图片地址(用于获取图片基本信息)
def get_img_service_path_by_pic_id(pid, bucket):
    picture = db.session.query(Picture).filter(Picture.id == pid) \
        .first()
    if picture:
        if not picture.path:
            return None
        if picture.path.startswith('http://'):
            return picture.path
        else:
            length = len(picture.path)
            path = picture.path
            object_key = path[17:length]
            full_oss_url = 'http://' + bucket + '.img-cn-qingdao.aliyuncs.com' + '/' + object_key + '@info'
            return full_oss_url
    else:
        return None


# 主要解决url 中 querystring 不同而缓存不变的问题
def make_cache_key(*args, **kwargs):
    path = request.path
    args_items = request.args.items()
    args = str(hash(frozenset(args_items)))
    # lang = get_locale()
    key = (path + args)
    return key
