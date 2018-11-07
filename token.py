# -*- coding: utf-8 -*-
__author__ = 'bliss'

from flask import jsonify, request, g
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature
from flask import current_app



api = ApiBlueprint('token')


@api.route('', methods=['POST'])
def get_token():
    """获取令牌"""
    # uid = g.uid
    form = GetTokenForm.create_api_form()
    uid_scope = verify_user(form.account.data, form.secret.data, form.type.data)

    expiration = current_app.config['TOKEN_EXPIRES_IN']
    token = generate_auth_token(uid_scope[0], form.type.data, uid_scope[1], expiration)
    return jsonify({'token': token.decode('ascii')}), 201


@api.route('/info', methods=['POST'])
def get_token_info():
    """获取令牌信息"""
    json = request.get_json(force=True, silent=True)
    if not json:
        raise JSONStyleError()
    else:
        s = Serializer(current_app.config['SECRET_KEY'])
        token = json['token']
        try:
            data = s .loads(token, return_header=True)
        except SignatureExpired:
            raise AuthFailed(error='token is expired', error_code=1003)
        except BadSignature:
            raise AuthFailed(error='token is invalid', error_code=1002)


    return jsonify(r), 200


def refresh_token():
    pass


def verify_user(ac, secret, ac_type):
    """验证用户身份"""
    try:
        if isinstance(ac_type, int) or str.isnumeric(ac_type):
            ac_type = int(ac_type)
            ac_type = AccountTypeEnum(ac_type)
        else:
            ac_type = AccountTypeEnum[ac_type]
    except ValueError:
        raise ParamException(error='the type parameter is not in range')
    promise = {
                AccountTypeEnum.management: account.verify_in_admin,
                AccountTypeEnum.appointment: account.verify_in_subscriber,
                # AccountTypeEnum.user_csu_mobile: account.verify_in_csu_by_mobile,
                # AccountTypeEnum.user_org_mobile: account.verify_in_org_by_mobile,
                # AccountTypeEnum.user_stats_account: account.verify_in_stats_by_account,
        }
    return promise.get(ac_type)(ac, secret)



