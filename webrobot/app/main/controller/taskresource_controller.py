import os
from pathlib import Path

import requests
from bson.objectid import ObjectId
from flask import request, send_from_directory
from flask_restplus import Resource
from mongoengine import ValidationError

from ..config import get_config
from ..model.database import (QUEUE_PRIORITY_DEFAULT, QUEUE_PRIORITY_MAX,
                              QUEUE_PRIORITY_MIN, Task, TaskQueue, Test)
from ..util.dto import TaskResourceDto
from ..util.tarball import make_tarfile, pack_files
from ..util.errors import *

api = TaskResourceDto.api

TARBALL_TEMP = Path('temp')
UPLOAD_DIR = Path(get_config().UPLOAD_ROOT)
try:
    os.mkdir(UPLOAD_DIR)
except FileExistsError:
    pass


@api.route('/<task_id>')
@api.param('task_id', 'task id to process')
class TaskResourceController(Resource):
    @api.response(406, "Task resource doesn't exist.")
    def get(self, task_id):
        try:
            task = Task.objects(pk=task_id).get()
        except ValidationError as e:
            print(e)
            return error_message(EINVAL, 'Task ID incorrect'), 400
        except Task.DoesNotExist:
            return error_message(ENOENT, 'Task not found'), 404
        
        if task.upload_dir == '' or task.upload_dir == None:
            return error_message(ENOENT, 'Upload directory is empty'), 406

        if request.args.get('file', None):
            return send_from_directory(Path(os.getcwd()) / UPLOAD_DIR / task.upload_dir, request.args['file'])
        else:
            tarball = pack_files(task_id, UPLOAD_DIR / task.upload_dir, TARBALL_TEMP)
            if not tarball:
                return error_message(EIO, 'Packing task resource files failed'), 401
            else:
                tarball = os.path.basename(tarball)
                return send_from_directory(Path(os.getcwd()) / TARBALL_TEMP, tarball)

@api.route('/list/<task_id>')
@api.param('task_id', 'task id to process')
class TaskResourceList(Resource):
    @api.response(406, "Task resource doesn't exist.")
    def get(self, task_id):
        try:
            task = Task.objects(pk=task_id).get()
        except ValidationError as e:
            print(e)
            return error_message(EINVAL, 'Task ID incorrect'), 400
        except Task.DoesNotExist:
            return error_message(ENOENT, 'Task not found'), 404
        
        if task.upload_dir == '' or task.upload_dir == None:
            return error_message(ENOENT, 'Upload directory is empty'), 406

        if not os.path.exists(UPLOAD_DIR / task.upload_dir):
            return error_message(ENOENT, 'Task upload directory does not exist'), 404

        return os.listdir(UPLOAD_DIR / task.upload_dir)

@api.route('/')
class TaskResourceUpload(Resource):
    @api.doc('upload resource files associated with a task')
    def post(self):
        found = False

        if 'resource_id' in request.form:
            temp_id = request.form['resource_id']
        else:
            temp_id = str(ObjectId())
            os.mkdir(upload_dir / temp_id)

        for name, file in request.files.items():
            found = True
            filename = upload_dir / temp_id / file.filename
            file.save(str(filename))

        files = request.form.getlist('file')
        for f in files:
            ret = requests.get(f)
            if ret.status_code == 200:
                found = True
                filename = f.split('?')[1].split('=')[1]
                filename = upload_dir / temp_id / filename
                with open(filename, 'wb') as fp:
                    fp.write(ret.content)

        if not found:
            return error_message(ENOENT, 'No files are found in the request'), 404

        return {'status': 0, 'data': temp_id}
