# -*- coding: utf-8 -*-
from io import BytesIO
import qrcode

__author__ = 'bliss'

import hashlib
import datetime,  random
from flask import request, current_app
from .enums import MobileRaceEnum
from .error_code import Successful


def get_url_no_param():
    full_path = str(request.full_path)
    q_index = full_path.find('?')
    full_path = full_path[0:q_index]

    return full_path


def android_ipad_iphone(http_user_agent):

    if 'iPhone' in http_user_agent:
        return MobileRaceEnum.iphone

    if 'iPad' in http_user_agent:
        return MobileRaceEnum.ipad

    if 'Android' in http_user_agent:
        return MobileRaceEnum.android

    return MobileRaceEnum.other


def success_json(code=None, msg=None, error_code=None):
    url = request.method+'  ' + get_url_no_param()
    return Successful(url, code, msg, error_code).get_json()


def dict_to_url_param(params_dict):
    m = map(lambda k: (k[0]+'='+str(k[1])+'&'), params_dict.items())
    url_params = '?'+''.join(m)
    url_params = url_params[:-1]
    return url_params


def check_md5_password(password, raw):
    """原始密码同md5加密的密码进行校验"""
    if not password:
        return False
    md5_password = secret_password(raw)
    if md5_password == password:
        return True
    else:
        return False


def secret_password(raw):
    sha1 = hashlib.sha1()
    sha1.update(raw.encode('utf-8'))
    sha1_psw = sha1.hexdigest()

    md5_raw = sha1_psw + salt
    m = hashlib.md5()
    m.update(md5_raw.encode('utf-8'))
    password = m.hexdigest()

    return password


def make_an_bizid():
    """生成一个微秒级别的时间字符串，并附带一个100到999之间的随机数"""
    time_str = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    bizid = time_str + str(random.randint(100, 999))
    return bizid


def allowed_uploaded_file_type(filename):
    filename = filename.lower()
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in current_app.config['ALLOWED_FILE_EXTENSIONS']


    random_name = get_timestamp_with_random() + '.' + extension
    object_url = year_month_day() + '/' + random_name
    return object_url


def make_a_qrcode(uri):
    """生成一张二维码,返回一组bytes"""
    qr = qrcode.QRCode(
                        version=2,
                        error_correction=qrcode.constants.ERROR_CORRECT_L,
                        box_size=10,
                        border=1
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image()
    png_bytes = BytesIO()
    img.save(png_bytes, 'png')
    return png_bytes


    remote_addr = request.remote_addr
    if  == '115.29.44.35':
        return True
    else:
        return False








