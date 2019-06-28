import os
from app.main.config import get_config
from pathlib import Path

from ..model.database import *
from .errors import *

TEST_RESULTS_ROOT = 'test_results'
USER_SCRIPT_ROOT = 'user_scripts'
BACK_SCRIPT_ROOT = 'back_scripts'
USERS_ROOT = Path(get_config().USERS_ROOT)
UPLOAD_DIR = Path(get_config().UPLOAD_ROOT)
try:
    os.mkdir(UPLOAD_DIR)
except FileExistsError:
    pass
try:
    os.mkdir(USERS_ROOT)
except FileExistsError:
    pass


def get_test_result_path(task):
    return get_test_results_root(task) / str(task.id)

def get_test_results_root(task=None, team=None, organization=None):
    if task:
        if team or organization:
            print('team or organization should not used along wite task')
            return None
        organization = task.organization
        team = task.team

    result_dir = USERS_ROOT / organization.path
    if team:
        result_dir = result_dir / team.path
    result_dir = result_dir / TEST_RESULTS_ROOT
    return result_dir

def get_back_scripts_root(task=None, team=None, organization=None):
    if task:
        if team or organization:
            print('team or organization should not used along wite task')
            return None
        organization = task.organization
        team = task.team

    result_dir = USERS_ROOT / organization.path
    if team:
        result_dir = result_dir / team.path
    result_dir = result_dir / BACK_SCRIPT_ROOT
    return result_dir

def get_user_scripts_root(task=None, team=None, organization=None):
    if task:
        if team or organization:
            print('team or organization should not used along wite task')
            return None
        organization = task.organization
        team = task.team

    result_dir = USERS_ROOT / organization.path
    if team:
        result_dir = result_dir / team.path
    result_dir = result_dir / USER_SCRIPT_ROOT
    return result_dir

def get_upload_files_root(task):
    return UPLOAD_DIR / task.upload_dir