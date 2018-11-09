"""
"""

import json
from flask import request
from flask import send_from_directory, abort
import os
from ..models.file import File
from ..models.base import db
from werkzeug.exceptions import RequestEntityTooLarge
from ..libs.bpbase import ApiBlueprint, auth
from ..libs.error_code import ParamException
from ..settings import EXPERIMENT_FILE_FOLDER
from werkzeug import secure_filename
from ..libs.error_code import FileUploadFailed
from ..libs.util import get_timestamp_with_random

api = ApiBlueprint('file')

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'xls', 'docx', 'doc', 'xlsx'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@api.route('', methods=['POST'])
# @auth.login_required
def upload_object():
    '''
        上传文件，key必须为file，只支持单文件上传
    '''
    if request.method == 'POST':
        file = request.files['file']
        if not file:
            return FileUploadFailed(error='文件接收失败')

        if file and allowed_file(file.filename):
            if not os.path.exists(EXPERIMENT_FILE_FOLDER):
                os.makedirs(EXPERIMENT_FILE_FOLDER)
            real_filename = file.filename

            # 文件名需要保证唯一
            storage_name = get_timestamp_with_random() + '.' + real_filename.rsplit('.', 1)[1]

            folder_path = __create_time_folder(EXPERIMENT_FILE_FOLDER)
            file.save(os.path.join(EXPERIMENT_FILE_FOLDER, folder_path, storage_name))
            file_modle = File()
            file_modle.ori_name = real_filename
            file_modle.name = storage_name
            file_modle.path = folder_path
            db.session.add(file_modle)
            db.session.commit()
            r = {
                'file_id': file_modle.id
            }
            headers = {'Content-Type': 'application/json'}
            return json.dumps(r), 200, headers
        else:
            return FileUploadFailed(error='不支持此类型的文件')


def __create_time_folder(root_folder):
    import datetime
    folder = datetime.date.today().strftime('%Y-%m-%d')
    full_path = os.path.join(root_folder, folder)
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    return folder


@api.route('/<int:id>', methods=['GET'])
# @auth.login_required
def download(id):
    '''
        下载文件
    '''
    if request.method == "GET":
        file = db.session.query(File).filter_by(id=id).first()
        path = EXPERIMENT_FILE_FOLDER + '\\' + file.path
        if os.path.isfile(path + '\\' + file.name):
            return send_from_directory(path, file.name, as_attachment=True)
        abort(404)
