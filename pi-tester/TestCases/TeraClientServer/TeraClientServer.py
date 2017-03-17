# -*- coding: utf-8 -*-
import pdb
import os
import traceback
import subprocess
import time
import re
import jwt
import json
import requests
import ast

import requests.packages.urllib3
from subprocess import PIPE
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pymongo import MongoClient
from bson.objectid import ObjectId

import config as CONFIG
import hb_crypt

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

CURRENT_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class InitTerafonnWebServer(object):

    """
    Provide initial realted functions for hcfs Terafonn Web Server.
    """

    def __init__(self):

        # Fake ArkFlex U Server
        self.fake_arkflex_path = os.path.join(
            CURRENT_FILE_PATH, 'fake_arkflex_api_server')
        self.fake_arkflex_path_name = os.path.join(
            self.fake_arkflex_path, 'fake_arkflex_api_server.py')

        # Fake Swift Server
        self.fake_swift_path = os.path.join(
            CURRENT_FILE_PATH, 'fake_swift_server')
        self.fake_swift_path_name = os.path.join(
            self.fake_swift_path, 'fake_swift_server.py')

        # Controller_Server
        self.Controller_Server_path = CURRENT_FILE_PATH + '/controller_server'
        self.Controller_Server = os.path.join(
            self.Controller_Server_path, 'controller_server.py')

        # docker related infoxw
        self.hcfsmgmt_server_docker_name = 'hcfsmanagementserver_web_1'
        self.oauth_py_in_docker = self.hcfsmgmt_server_docker_name + \
            ':/usr/local/lib/python2.7/dist-packages/social/backends/oauth.py'
        self.backup_oauth_py = os.path.join(
            CURRENT_FILE_PATH, 'oauth.py.origin')
        self.fake_oauth_py = os.path.join(CURRENT_FILE_PATH, 'fake_oauth.py')

        # Test data
        self.test_data_path = os.path.join(
            CURRENT_FILE_PATH, 'test_data')

    def Launch_Terafonn_Web_Server(self):
        try:
            print('Launch_Terafonn_Web_Server')

            print os.popen('docker exec -i -t env_tornado_1 python3 run.py').read()

        except:
            traceback.print_exc()
            raise Exception('Launch Terafonn Web Server fail.')

    def kill_Terafonn_Web_Server(self):
        try:
            result = os.popen(
                "ps -ef | grep python3\ run.py | grep -v grep | awk '{print $2}'").read().strip()
            if result:
                subprocess.call(['kill', str(result)])
        except:
            traceback.print_exc()
            raise Exception('Kill Terafonn Web Server fail.')

    def launch_fake_arkflex_server(self):
        try:
            r = requests.get('http://' + CONFIG.DEFAULT_BACKEND['api_domain'])
        except:
            print 'launch_fake_arkflex_server'
            p = subprocess.Popen(
                ['python', self.fake_arkflex_path_name, '&'])

    def kill_fake_arkflex_server(self):
        try:
            result = os.popen(
                "ps -ef | grep python\ " +
                self.fake_arkflex_path_name +
                " | grep -v grep | awk '{print $2}'").read().strip()
            if result:
                subprocess.call(['kill', str(result)])
        except:
            raise Exception('kill fake arkflex server failed!')

    def launch_fake_swfit_server(self):
        try:

            r = requests.get(
                'http://' +
                CONFIG.DEFAULT_BACKEND['domain'] +
                ':8080')
        except:
            print 'launch_fake_swfit_server'
            p = subprocess.Popen(
                ['python', self.fake_swift_path_name, '&'])
            FAKE_SWIFT_PID = p.pid

    def kill_fake_swfit_server(self):
        try:
            result = os.popen(
                "ps -ef | grep python\ " +
                self.fake_swift_path_name +
                " | grep -v grep | awk '{print $2}'").read().strip()
            if result:
                subprocess.call(['kill', str(result)])

        except:
            raise Exception('kill fake swfit server failed!')

    def Launch_Controller_Server(self):

        try:

            print('Launch Controller Server')

            p = subprocess.Popen(['python', self.Controller_Server])

        except:
            traceback.print_exc()
            raise Exception('Launch Terafonn Web Server fail.')

    def kill_Controller_Server(self):
        try:
            print('kill Controller Server')

            command_result = os.popen(
                "ps -ef | grep python\ " +
                self.Controller_Server +
                " | grep -v grep | awk '{print $2}'").read().strip()
            if command_result:
                subprocess.call(['kill', str(command_resultcommand_result)])
        except:
            traceback.print_exc()
            raise Exception('Kill Controller Server fail.')

    def kill_docker(self, docker_name):
        try:

            r = os.popen('docker ps |grep env_frontend-dev').read()

            if r:
                command_result = os.popen(
                    "docker kill " + str(docker_name)).read().strip()
                if command_result:
                    subprocess.call(['kill', str(command_result)])
        except:
            traceback.print_exc()
            raise Exception('Kill docker fail.')

    def copy_file_docker_local(self, source, dest):
        copy_cmds = ['sudo', 'docker', 'cp', source, dest]
        try:
            subprocess.call(copy_cmds)
        except:
            raise Exception('Copy file between docker and local failed!')

    def copy_meta_data(self, source, dest):

        source_path = os.path.join(
            self.test_data_path, source)
        dest_path = os.path.join(
            self.test_data_path, dest)

        copy_cmds = ['cp', source_path, dest_path]
        try:
            subprocess.call(copy_cmds)
        except:
            raise Exception('Copy file failed!')

    def restart_service_in_docker(self):
        restart_cmds = [
            'sudo', 'docker', 'exec', '-it',
            self.hcfsmgmt_server_docker_name,
            '/usr/bin/supervisorctl', 'restart', 'all',
        ]
        try:
            print 'Restart service in docker'
            subprocess.call(restart_cmds)
        except:
            raise Exception('Restart the service in docker failed!')

    def patch_gauth_client(self):
        print 'Start patch gauth client'
        self.copy_file_docker_local(
            self.fake_oauth_py,
            self.oauth_py_in_docker)

        self.restart_service_in_docker()

    def restore_gauth_client(self):
        self.copy_file_docker_local(
            self.backup_oauth_py,
            self.oauth_py_in_docker)

        self.restart_service_in_docker()

    def reset_mongodb(self):

        try:

            print('reset mongodb')
            db_name = ['teraclient-mongodb-dev', 'teraclient-mongodb-test']
            for db_item in db_name:

                command = 'echo "db.runCommand( { dropDatabase: 1 } )" | mongo %s:27017/teraclient' % (
                    db_item)
                os.popen(command)
                # command = 'echo "lib/mongodb/init.js" | mongo %s:27017/teraclient' % (db_item)

        except:
            traceback.print_exc()
            raise Exception('reset mongodb fail.')

    def check_inode_by_mongo(self, imei, inode, start, length):

        query = "{'imei':'%s','inode':%s}" % (imei, json.dumps(inode))

        db_name = ['teraclient-mongodb-dev', 'teraclient-mongodb-test']
        for i in db_name:

            command = 'echo "db.cache_inode_meta.find({0}).skip({1}).limit({2})" | mongo {3}:27017/teraclient'.format(
                query, json.dumps(start), json.dumps(length), i)
            command_result = os.popen(command).read().strip().split('\n')

            if 'failed' in command_result[2]:
                continue
            else:
                db_check = command_result
                break

        try:
            if db_check and len(db_check) < 4:

                return (0, 'Inode not exist')
            else:
                return (1, 'Inode exist')
        except NameError as e:
            return (2, 'Can\'t connect to any DB')
        except Exception as e:
            return (3, 'Check inode error , msg:{0}'.format(str(e)))

    def generate_file_md5(self, file_name):

        if not os.path.isfile(file_name):
            return (False, str(file_name) + ' not exist')

        command = 'md5sum "{0}"'.format(file_name)
        # print command
        command_result = os.popen(command).read().split(file_name)[0].strip()

        return True, command_result

    @staticmethod
    def read_files_rb(files_name):

        feedback_path = os.path.join(CURRENT_FILE_PATH, 'test_data/feedback')
        feedback_name = os.path.join(feedback_path, files_name)

        fileobj = open(feedback_name, 'rb')

        return fileobj


class MongodbWorker(object):

    def __init__(self, mongo_uri='', db_name='', table_name=''):

        client = MongoClient(mongo_uri) if mongo_uri else MongoClient(
            "mongodb://teraclient-mongodb:27017")
        db = client[db_name] if db_name else client['teraclient']
        self.collect = db[table_name] if table_name else db['session']

    def get_session_id(self):

        session_id = []

        for i in self.collect.find():

            if i['data']['google'][
                    'access_token'] == 'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw':
                session_id.append(i['_id'])

        return session_id if session_id else False

    def inert_session_id(self, jwt_secret=''):

        jwt_secret = jwt_secret if jwt_secret else "Mvs7kuTPCs5qdC8PNHMMTVSFvY6PEwLDJDgmmJTzUtPV6zkq2kzDpjTYK4stpg49"

        now_ts = int(time.time())

        google_token = {
            u'cached_ts': now_ts,
            u'data': {
                'google': {
                    u'expires_in_ts': 1478851262,
                    u'access_token': u'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw',
                    u'id_token': u'eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ1MjA4ODBiNDYzNGE1YTNjNDFiNWNmNjU1M2U5ZWE0YTViNjA5ZjIifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNDc4NzQzNTA2LCJleHAiOjE0Nzg3NDcxMDYsImF0X2hhc2giOiJncGxDZkZfdW1XOElhMnpyRl9KQXRnIiwiYXVkIjoiNzk1NTc3Mzc3ODc1LTM4bGFhYWd1NDVyN3IyMjdhZ2F1azUyMTZ1cmtiMHFoLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTExODgwNDQ4ODMxNzE1OTMxNTcyIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF6cCI6Ijc5NTU3NzM3Nzg3NS0zOGxhYWFndTQ1cjdyMjI3YWdhdWs1MjE2dXJrYjBxaC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImhkIjoiaGFwcHlnb3JnaS5jb20iLCJlbWFpbCI6ImplcmVteS53dUBoYXBweWdvcmdpLmNvbSJ9.dIfgUtjB9XadO__gF5zZDjVarsbsJTGdPGo3t-vq0Py_vyX1b035vaB4lPEfedt5QBMLHwf4K6m3wqtyIGH4gYaLP6lWl9vW1njoW3184DM4sNncDLnXehceBn1vttqRCfNhEkhjURD671geZvVjx1FHrNmCW3EgoW2T74Nh3uj-t1HMPvQ_WHFYnA7lQaATRglaF7SDr9IDFQ0VX30tDGoT8kIzgMba3P2Y74AlLdPrFfnP7KrrKXn5sthh9Rg53f6UBP2wYC6hfbdoUA_hklqn68wSkqC0KyKOY2Nybx5pNsV9QlBtui5tcXjDCandMVwOOoJmnaanLn8P32lH6w',
                    u'expires_in': 3600,
                    u'token_type': u'Bearer',
                    u'refresh_token': u'1/ocn8sYu64Y4F2dU0gyOxSL8OI7HnRcAJs15UjgD2JOGNzN5VDC4W1UUkkDaMY0C-'}}}
        google_token['data']['google']['expires_in_ts'] = google_token[
            'data']['google']['expires_in'] + now_ts

        session_id = self.collect.insert_one(google_token).inserted_id

        # print('session_id:\n{0}'.format(session_id))

        jwt_data = {'session_id': str(session_id)}

        jwt_token = jwt.encode(
            jwt_data,
            jwt_secret,
            algorithm='HS256').decode('utf-8')

        # print('jwt_token:\n{0}'.format(jwt_token))

        return jwt_token

    def del_session_id(self, session_id=None):

        if isinstance(session_id, list):
            for i in session_id:
                # print('del {0}...'.format(i))
                self.collect.remove({"_id": i})
        elif isinstance(session_id, basestring):
            # print('del {0}'.format(session_id))
            self.collect.remove({'_id': ObjectId(session_id)})

        else:
            session_id = self.get_session_id()
            for i in session_id:
                # print('del {0}...'.format(i))
                self.collect.remove({"_id": i})
   


class DockerWorker(object):

    def check_ps_in_running(self, ps):

        command_result = os.popen(
            'docker ps --filter status=running |grep ' + ps).read()
        if command_result:
            return (True, 'ps in running')
        else:
            return (False, 'ps not running')

    def check_inode(self, imei, inode, start, length):

        print('check inode')

        mytera_db = os.popen(
            "docker ps --format '{{.Names}}' |grep teraclient-mongodb").read().strip()

        query = "{'imei':'%s','inode':%s}" % (imei, json.dumps(inode))

        command = 'docker exec -i -t {0} mongo meta_data --eval "db.meta.find({1}).skip({2}).limit({3})"'.format(
            mytera_db, query, json.dumps(start), json.dumps(length))

        command_result = os.popen(command).read().strip().split('\n')

        if len(command_result) < 3:

            return (False, 'Inode not exist')
        else:
            return (True, 'Inode exist')


class APIRequestWorker(object):

    """
    Wrapper of REST APIs
    """

    def __init__(self, path=None, token=None):

        self.path = '' if path is None else path
        self.url = CONFIG.TERA_CLIENT_HOST_URL + self.path

    def parse_response(self, r):

        self.result = True if r.status_code < 399 else False
        self.status_code = r.status_code
        self.text = r.text

        try:
            self.json = r.json()
        except:
            self.json = {}

        return self

    def get_auth_token_by_user(self, username, password):

        headers = {'Content-Type': 'application/json'}
        data = {'username': username, 'password': password}
        url = CONFIG.MANAGMENT_HOST_URL + '/api/auth/'

        r = requests.post(
            url,
            headers=headers,
            data=json.dumps(data),
            verify=False)

        if r.status_code == 200:

            return r.json()['token']
        else:
            return None

    def get_social_oauth_token(self, token):
        headers = {'Content-Type': 'application/json'}
        data = {"backend": 'google-oauth2', "code": token}

        url = CONFIG.MANAGMENT_HOST_URL + '/api/social-auth/'
        r = requests.post(
            url,
            headers=headers,
            data=json.dumps(data),
            verify=False)

        if r.status_code == 200:
            return r.json()['token']
        else:
            return None

    def get_gauth_token(self):

        if not os.path.exists(CURRENT_FILE_PATH + '/token.json'):

            # get token by selenium
            self.selenium_worker = SeleniumWorker()
            self.gauth_token = self.selenium_worker.take_gauth_token()

            with open(CURRENT_FILE_PATH + '/token.json', 'w') as f:
                f.write(json.dumps(self.gauth_token))

        else:

            with open(CURRENT_FILE_PATH + '/token.json', 'r') as f:
                output = json.load(f)
                self.gauth_token = output
                print self.gauth_token

        return self.gauth_token

    def get_auth_token(self, username='hopebaytest1@gmail.com'):

        url = CONFIG.TERA_CLIENT_HOST_URL + '/api/login'

        gauth_token = username

        data = {'access_token': gauth_token}

        r = requests.post(url, data=json.dumps(data), verify=False)

        return r.json()['token']

    def set_header(self, header):
        self.headers = header

    def set_data(self, parameter):

        self.data = json.dumps(parameter)

    def set_files(self, attachments='', meta=''):

        files = []
        meta_tuple = ('feedback',(None, json.dumps(meta),'application/json'))
        files.append(meta_tuple)

        if attachments != '':

            if isinstance(attachments, list):

                for attachments_items in attachments:

                    fileobj = InitTerafonnWebServer.read_files_rb(
                        attachments_items)

                    attachments_tuple =  ('attachments',(str(attachments_items), fileobj))

                    files.append(attachments_tuple)

            elif isinstance(attachments, basestring):

                fileobj = InitTerafonnWebServer.read_files_rb(attachments)

                attachments_tuple = ('attachments',(str(attachments), fileobj))

                files.append(attachments_tuple)


            else:
                raise TypeError('Attachments input error , Need list or str')
        self.files = files

    # Setup environment for request
    def create_backend(self, data):

        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/backends/'
        r = requests.post(
            url,
            headers=self.headers,
            data=json.dumps(data),
            verify=False)

        if r.status_code > 399 and not re.search(r'.+unique set.+', r.text):
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def query_backend_by_domain(self, domain):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/backends/'
        r = requests.get(url, headers=self.headers, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            resp = r.json()
            for item in resp:
                if item['domain'] == domain:
                    return item
            return None

    def delete_backend_by_id(self, backend_id):
        url = CONFIG.MANAGMENT_HOST_URL + \
            '/api/register/backends/' + str(backend_id) + '/'
        r = requests.delete(url, headers=self.headers, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def delete_backend_by_domain(self, domain):
        item = self.query_backend_by_domain(domain)
        backend_id = item['id']
        return self.delete_backend_by_id(backend_id)

    def create_model(self, data):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/models/'
        r = requests.post(
            url,
            headers=self.headers,
            data=json.dumps(data),
            verify=False)
        if r.status_code > 399 and not re.search(r'.+unique set.+', r.text):
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def query_model(self):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/models/'
        r = requests.get(url, headers=self.headers, verify=False)
        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def delete_model_by_desc(self, desc):

        resp = self.query_model()
        ID = None
        for i in resp.json():
            ID = str(i['id']) if i['desc'] == desc else '00'

        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/models/' + ID + '/'
        r = requests.delete(url, headers=self.headers, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def create_device(self, data):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/devices/'
        r = requests.post(
            url,
            headers=self.headers,
            data=json.dumps(data),
            verify=False)

        if r.status_code > 399:
            resp_data = r.json()

            if resp_data and (
                    resp_data['imei'] == ['Device with this imei already exists.']):
                return r
            else:
                raise Exception(
                    'HTTP error code: {0}, Response: {1}'.format(
                        r.status_code, r.text))
        else:
            return r

    def query_devices(self):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/devices/'
        r = requests.get(url, headers=self.headers, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def delete_device(self, imei):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/devices/' + imei + '/'
        r = requests.delete(url, headers=self.headers, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def close_device(self, imei):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/user/devices/' + imei + '/close/'
        r = requests.post(url, headers=self.headers, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def register_user(self, data):

        encrypt_imei = hb_crypt.encrypt(data['imei_code'])
        result = re.search(r'(.+\=\=).+', encrypt_imei)

        imei_code = result.group(1) if result else encrypt_imei

        data.update({'imei_code': imei_code})

        url = CONFIG.MANAGMENT_HOST_URL + '/api/user/devices/'

        r = requests.post(url, headers=self.headers, json=data, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def query_account_id_by_account_name(self, account_name):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/accounts/'
        r = requests.get(url, headers=self.headers, verify=False)
        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            resp_data = r.json()
            id_list = []
            if resp_data:
                for account_info in resp_data:
                    id_list.append(account_info['id'])
                return id_list

            raise Exception('User id not found!')

    def delete_account_by_id(self, account_id):
        url = CONFIG.MANAGMENT_HOST_URL + \
            '/api/register/accounts/' + str(account_id) + '/'

        r = requests.delete(url, headers=self.headers, verify=False)
        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}, url: {2}'.format(
                    r.status_code, r.text, url))
        else:
            return r

    def delete_account_by_name(self, account_name):
        account_id = self.query_account_id_by_account_name(account_name)

        if account_id:
            for i in account_id:
                result = self.delete_account_by_id(i)
            return result
        else:
            return Exception('User id not found!')

    def query_user_devices(self):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/user/devices/'
        r = requests.get(url, headers=self.headers, verify=False)

        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def create_activation_code(self, data):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/activation_codes/'
        r = requests.post(
            url,
            headers=self.headers,
            data=json.dumps(data),
            verify=False)
        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def query_activation_code(self):
        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/activation_codes/'
        r = requests.get(url, headers=self.headers, verify=False)
        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        else:
            return r

    def get_available_activation_code(
            self,
            num=None,
            state=None,
            model=None,
            pages=None):

        url = CONFIG.MANAGMENT_HOST_URL + '/api/register/activation_codes/'

        if pages:
            url += '?page=' + str(pages)

        r = requests.get(url, headers=self.headers, verify=False)

        count = 0
        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}'.format(
                    r.status_code, r.text))
        if num:
            for item in r.json()['results']:
                if count == num:
                    return item['code']
                count += 1
        else:
            for item in r.json()['results']:
                if item['state'] == state and item['model'] == model:
                    return item['code']
                if item['state'] == 'not activated' and item[
                        'model'] == model and (state is None):
                    return item['code']
                if item['state'] == state and (model is None):
                    return item['code']
                if item['state'] == 'not activated':
                    return item['code']
        return None

    def delete_activation_code(self, code):

        url = CONFIG.MANAGMENT_HOST_URL + \
            '/api/register/activation_codes/' + str(code) + '/'
        r = requests.delete(url, headers=self.headers, verify=False)
        if r.status_code > 399:
            raise Exception(
                'HTTP error code: {0}, Response: {1}, url: {2}'.format(
                    r.status_code, r.text, url))
        else:
            return r

    # Basic request
    def get(self, path=None):

        if path is not None:
            url = CONFIG.TERA_CLIENT_HOST_URL + path
        else:
            url = self.url

        r = requests.get(url, headers=self.headers, verify=False)

        return self.parse_response(r)


    def download(self, path=None, data_name=None):

        if path is not None:
            url = CONFIG.TERA_CLIENT_HOST_URL + path
        else:
            url = self.url

        cookies = {
            "access-token": self.headers['X-Access-Token'],
            "imei": self.headers['X-Imei']}
        r = requests.get(
            url,
            cookies=cookies,
            headers=self.headers,
            verify=False)

        self.result = True if r.status_code < 399 else False
        self.status_code = r.status_code

        if self.result:
            # save data
            with open('./' + data_name, 'w') as f:
                f.write(r.content)
        else:
            self.text = r.text
            try:
                self.json = r.json()
            except:
                self.json = {}

        return self

    def post(self):

        r = requests.post(
            self.url,
            headers=self.headers,
            data=self.data,
            verify=False)

        return self.parse_response(r)

    def post_files(self):

        r = requests.post(
            self.url,
            headers=self.headers,
            files=self.files)

        return self.parse_response(r)

    def put(self):
        r = requests.put(
            self.url,
            headers=self.headers,
            data=self.data,
            verify=False)

        return self.parse_response(r)

    # General actions
    def lock_devices(self, imei):

        url = CONFIG.TERA_CLIENT_HOST_URL + '/api/device/lock'
        auth_token = self.get_auth_token()
        headers = {'X-Access-Token': auth_token}
        data = {'imei': imei}
        r = requests.get(
            url,
            headers=headers,
            data=json.dumps(data),
            verify=False)

        return self.parse_response(r)


class TeraClientServer_00000:

    '''
    Initial Tera Client Web server
    '''

    def __init__(self):
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker = APIRequestWorker()
        self.dockerworker = DockerWorker()

        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = 353627076182982
        self.auth_token = self.apiworker.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker.set_header(self.api_headers)

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

    def create_new_device(self, imei='353627076182982'):

        available_activation_code = self.get_available_activation_code()

        api_headers = {
            'Authorization': 'JWT ' + self.social_oauth_token,
            'Content-Type': 'application/json'
        }

        self.MODEL = self.apiworker.query_model().json()[0]['id']

        self.apiworker.set_header(api_headers)
        self.apiworker.register_user({
            "imei_code": imei,
            "activation_code": available_activation_code,
            "force": False,
            "vendor": "HopeBay",
            "model": 'test_model',
            "android_version": "6.0.1",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def get_available_activation_code(self):

        # init - admin info
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        # get available activation code by admin
        self.auth_token_admin = self.apiworker.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token_admin,
            'Content-Type': 'application/json'
        }
        self.apiworker.set_header(self.api_headers)

        return self.apiworker.get_available_activation_code()

    def create_devices(self, count):
        imei = self.imei
        for i in range(1, count):
            imei = int(imei) + 1
            self.create_new_device(str(imei))

    def run(self):

        # Setup Environment
        self.apiworker.create_backend(CONFIG.DEFAULT_BACKEND)

        self.apiworker.create_model(CONFIG.DEFAULT_MODEL)
        self.MODEL = self.apiworker.query_model().json()[0]['id']
        CONFIG.DEFAULT_DEVICES['model'] = self.MODEL
        self.apiworker.create_device(CONFIG.DEFAULT_DEVICES)
        CONFIG.DEFAULT_ACTIVATION_CODE['model'] = self.MODEL
        self.apiworker.create_activation_code(CONFIG.DEFAULT_ACTIVATION_CODE)
        self.apiworker.register_user({
            "imei_code": CONFIG.DEFAULT_IMEI,
            "model": self.MODEL,
            "force": False,
            "vendor": "HopeBay",
            "android_version": "1.0.0",
            "HCFS_version": "4.3.2.1111",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

        # Create Tester account & device
        self.create_new_device()
        self.create_devices(4)

        return (True, '')

'''
TeraClient - Server API
'''


class TeraClientServer_01001:

    '''
    POST /api/login
    '''

    def __init__(self):
        self.mongowkrker = MongodbWorker()
        self.verity_username = "Jeremy Wu"
        self.verity_email = 'Tester@gmail.com'

        self.apiworker = APIRequestWorker('/api/login/')
        self.apiworker.set_header(None)

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_data({'access_token': str(self.session_id)})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):
        if r.json and (r.result):

            try:
                if r.json['username'] == self.verity_username and r.json[
                        'email'] == self.verity_email and r.json['user_id'] and r.json['token']:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):
        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_01002:

    '''
    GET /api/devices
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()

        self.apiworker = APIRequestWorker('/api/devices')

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['devices'] and len(r.json['devices']) == 4:
                    for device_i in r.json['devices']:
                        if sorted(
                            device_i.keys()) == sorted(
                            [
                                u'expiration_date',
                                u'imei',
                                u'last_sync',
                                u'name',
                                u'registration_date',
                                u'service_state',
                                u'status',
                                u'total_space',
                                u'used_space',
                                u'webdav_state']):
                            return True, ''
                        else:
                            return False, 'devices key error, msg:{0}'.format(
                                sorted(device_i.keys()))
                else:
                    return False, 'Devices number error , msg:{0}'.format(
                        len(r.json['devices']))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.get()

        # self.teardown()

        return self.parse_response(r)


class TeraClientServer_01003:

    '''
    GET /api/files

    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 1
        self.verity_records_total = 1

        self.apiworker = APIRequestWorker('/api/files')

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {"inode": 197, "name": "Music", }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):

            try:
                if r.json['files'] and len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_01004:

    '''
    POST /api/device/lock
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei})

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def teardown(self):

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})

        apiworker.post()

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_lock():

            result = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_01005:

    '''
    POST /api/device/unlock
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/unlock')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei})

    def verify_device_unlock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')
        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:

                if str(i['service_state']) != 'activated':
                    return True
        return False

    def setup(self):

        apiworker = APIRequestWorker('/api/device/lock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

    def teardown(self):

        # unlock
        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_unlock():
            result = (
                False,
                'Device unlock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))
        if result[0] is False:
            self.teardown()

        return result


class TeraClientServer_01006:

    '''
    POST /api/device/erase
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/erase')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei})

    def verify_device_erase(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')
        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True, r.status_code

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled_n_wipe':
                    return True, str(i['service_state'])
        return False, ''

    def setup(self):

        apiworker = APIRequestWorker('/api/device/lock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

    def teardown(self):

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        return True, '' if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        result = self.parse_response(r)

        erase_result = self.verify_device_erase()

        if erase_result[0]:
            result = (
                False,
                'mgmt status error. status info : {0}'.format(
                    erase_result[1]))

        self.teardown()

        return result


class TeraClientServer_01007:

    '''
    GET /api/file/{inode}/download
    Verify pdf data
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.data_inode = '9230'
        self.file_name = '4x3_HBMobile.pptx'
        self.file_md5 = 'c768cc5bd5a2a3895c5ba58ec8dd9760'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, 'X-Imei': self.imei})

    def teardown(self):

        self.mongowkrker.del_session_id()

        if os.path.isfile(self.file_name):
            os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:

            result, download_files_md5 = self.terafonn_web_server.generate_file_md5(self.file_name)
            
            if result and self.file_md5 == download_files_md5:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):
        
        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_01008:

    '''
    GET /api/files/{inode}/info
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.meta_inode = '9230'
        self.size = 254005

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.meta_inode + '/info')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, 'X-Imei': self.imei})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['a_time'] and r.json['c_time'] and r.json[
                        'm_time'] and r.json['size'] == self.size:
                    return True, ''
                else:
                    return False, 'SizeError , size:"{0}",not "{1}"'.format(
                        r.json['size'], self.size)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.get()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_01009:

    '''
    POST /api/webdav/enable
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.new_password = 'Aa123456'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/webdav/enable')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei})

    def verify_device_erase(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')
        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True, r.status_code

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled_n_wipe':
                    return True, str(i['service_state'])
        return False, ''

    def setup(self):

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        apiworker_setup.put()

    def teardown(self):

        apiworker_setup = APIRequestWorker('/api/webdav/disable')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data({'imei': self.imei})
        apiworker_setup.post()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()
        self.verify_device_erase()
        return self.parse_response(r)


class TeraClientServer_01010:

    '''
    POST /api/webdav/disable
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.new_password = 'Aa123456'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/webdav/disable')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei})

    def setup(self):

        # Set password
        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        apiworker_setup.put()

        # Enable webdav
        apiworker_setup = APIRequestWorker('/api/webdav/enable')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data({'imei': self.imei})
        apiworker_setup.post()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_01011:

    '''
    PUT /api/webdav/
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182983"
        self.new_password = 'Aa123456'

        self.session_id = self.mongowkrker.inert_session_id()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data(
            {'imei': self.imei, 'new_password': self.new_password})

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.put()

        return self.parse_response(r)


class TeraClientServer_01012:

    '''
    GET /api/webdav/
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.new_password = 'Aa123456'
        self.tester_name = 'Tester@gmail.com'

        self.session_id = self.mongowkrker.inert_session_id()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, 'X-Imei': self.imei})

    def setup(self):

        # Set password
        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        apiworker_setup.put()

        # Enable webdav
        apiworker_setup = APIRequestWorker('/api/webdav/enable')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data({'imei': self.imei})
        apiworker_setup.post()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['url'] and r.json['username'] == self.tester_name:
                    return True, ''
                else:
                    return False, 'Username Error , username is {0},not {1}'.format(
                        r.json['username'], self.tester_name)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.get()

        return self.parse_response(r)


class TeraClientServer_01013:

    '''
    POST /api/feedback
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name, self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['attachments'] and r.json['name'] == self.meta['name'] and r.json['email'] == self.meta['email'] and r.json['phone'] == self.meta['phone'] and r.json['origin_of_issue'] == self.meta['origin_of_issue'] and r.json[
                        'device_model'] == self.meta['device_model'] and r.json['web_browser'] == self.meta['web_browser'] and r.json['category'] == self.meta['category'] and r.json['description'].encode('utf-8') == self.meta['description']:
                    return True, ''
                else:
                    return False, 'meta contents not same, response contents:{0}'.format(
                        r.json)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        # self.teardown()

        return self.parse_response(r)

'''
Integration Test
'''


class TeraClientServer_02001:

    '''
    GET /api/devices
    Verify latest sync time
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()

        self.apiworker = APIRequestWorker('/api/devices')

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})

    def get_first_time(self):

        r = self.apiworker.get()
        self.first_sync_time = r.json['devices'][0]['last_sync']

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):
        if r.json and (r.result):
            try:
                if int(
                        r.json['devices'][0]['last_sync']) > int(
                        self.first_sync_time):
                    return True, ''
                else:

                    return False, 'sync time error, first sync time:{0} , second sync time:{1}'.format(
                        self.first_sync_time, r.json['devices'][0]['last_sync'])

            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.get_first_time()

        time.sleep(1)

        r = self.apiworker.get()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02002:

    '''
    POST /api/files
    Verify params of start over file count
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 4
        self.length = 2
        self.verity_files_count = 0
        self.verity_records_total = 1

        self.apiworker = APIRequestWorker('/api/files')

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {"inode": 197, "name": "Music", }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02003:

    '''
    POST /api/files
    Verify mandatory params is none
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 16
        self.verity_records_total = 16
        self.verity_current_path = {"name": "/", "inode": 149}

        self.apiworker = APIRequestWorker('/api/files')

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.verity_current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02004:

    '''
    POST /api/files
    Verify mandatory params is null
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 16
        self.verity_records_total = 16
        self.verity_current_path = {u'inode': 149}

        self.apiworker = APIRequestWorker('/api/files')

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {}
        self.apiworker.set_data(
            {'imei': self.imei, 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):
        if r.json and (r.result):
            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.verity_current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02005:

    '''
    POST /api/files
    Device is locked
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 16
        self.verity_records_total = 16
        self.verity_current_path = {u'inode': 149}
        self.msg = 'service is not activated !'

        self.apiworker = APIRequestWorker('/api/files')

    def lock_device(self):

        apiworker = APIRequestWorker('/api/device/lock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {}
        self.apiworker.set_data(
            {'imei': self.imei, 'current_path': self.current_path})

    def teardown(self):

        # unlock
        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

        self.mongowkrker.del_session_id()

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.lock_device()

        r = self.apiworker.post()

        if self.verify_device_lock():
            r = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

            return r
        else:

            self.teardown()

            return self.parse_response(r)


class TeraClientServer_02006:

    '''
    POST /api/files
        Verity current_inode = 0 & one external vol
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 16
        self.verity_records_total = 16
        self.verity_current_path = {u'inode': 149}

        self.apiworker = APIRequestWorker('/api/files')

    def lock_device(self):

        apiworker = APIRequestWorker('/api/device/lock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {}
        self.apiworker.set_data(
            {'imei': self.imei, 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def parse_response(self, r):
        if r.json and (r.result):
            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.verity_current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02007:

    '''
    POST /api/files
    Verity next inode
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 9
        self.verity_records_total = 9
        self.verity_current_path = {
            "name": "Music",
            "next": {
                "name": "\\u97f3\\u6a02",
                "inode": 9185},
            "inode": 197}

        self.apiworker = APIRequestWorker('/api/files')

 
    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {
            "inode": 197,
            "name": "Music",
            "next": {"inode": 9185, "name": "\\u97f3\\u6a02"}
        }
        self.apiworker.set_data(
            {'imei': self.imei, 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.verity_current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02008:

    '''
    POST /api/files
    Verity next and next inode
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 9
        self.verity_records_total = 9
        self.verity_current_path = {
            "name": "Music",
            "next": {
                "name": "\\u97f3\\u6a02",
                "inode": 9185},
            "inode": 197}

        self.apiworker = APIRequestWorker('/api/files')

    def setup(self):
    
        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {"name": "Music","next": {"name": "\\u97f3\\u6a02","inode": 9185},"inode": 197}
        self.apiworker.set_data({'imei': self.imei, 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.verity_current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02009:

    '''
    POST /api/files
    Verity device locked
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_current_path = {
            "name": "Music",
            "inode": 197}
        self.error_msg = 'service is not activated !'

        self.apiworker = APIRequestWorker('/api/files')

    def lock_device(self):

        apiworker = APIRequestWorker('/api/device/lock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {
            "name": "Music",
            "inode": 197}
        self.apiworker.set_data(
            {'imei': self.imei, 'current_path': self.current_path})

    def teardown(self):

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})
        apiworker.post()

        self.mongowkrker.del_session_id()

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def parse_response(self, r):

        if r.json and (r.result is False):
            try:
                if r.json['message'] == self.error_msg:
                    return True, ''
                else:
                    return False, 'MessageError , msg is "{0}" ,not "{1}"'.format(
                        r.json['message'], self.error_msg)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.lock_device()

        r = self.apiworker.post()

        if self.verify_device_lock():
            r = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

            return r
        else:

            self.teardown()

            return self.parse_response(r)


class TeraClientServer_02010:

    '''
    POST /api/files
    Verity inode in cache
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 1
        self.verity_records_total = 1
        self.verity_current_path = {
            "name": "Music",
            "inode": 197}

        self.apiworker = APIRequestWorker('/api/files')


    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {
            "name": "Music",
            "inode": 197}
        self.apiworker.set_data(
            {'imei': self.imei, 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()


    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.verity_current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.apiworker.post()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)



class TeraClientServer_02011:

    '''
    POST /api/files
    Verity cache data is old
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.start = 0
        self.length = 20
        self.verity_files_count = 0
        self.verity_records_total = 0

        self.apiworker = APIRequestWorker('/api/files')

    def setup(self):

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.current_path = {"inode": 203, "name": "Notifications", }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'current_path': self.current_path})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):

            try:
                if len(r.json['files']) == self.verity_files_count and r.json['records_total'] == self.verity_records_total and r.json[
                        'start'] == self.start and r.json['length'] == self.length and r.json['current_path'] == self.current_path:
                    return True, ''
                else:
                    return (False, (r.status_code, r.text))
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        self.teardown()

        return self.parse_response(r)

class TeraClientServer_02012:

    '''
    POST /api/lock
    Verify Add en-US message (optional)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182985"
        self.message = 'test message'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei, 'message': self.message})

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def teardown(self):

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})

        apiworker.post()

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_lock():

            result = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02013:

    '''
    POST /api/lock
    Verify Add zh-TW message (optional)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182985"
        self.message = '哈哈哈，目前是鎖上機器時的訊息喔！'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei, 'message': self.message})

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def teardown(self):

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})

        apiworker.post()

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_lock():

            result = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02014:

    '''
    POST /api/device/lock
    Verify message is none
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182985"
        self.message = None

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei, 'message': self.message})

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def teardown(self):

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})

        apiworker.post()

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_lock():

            result = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02015:

    '''
    POST /api/device/lock
    Verify message is garbled
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()
        self.apiworker = APIRequestWorker()

        self.imei = "353627076182982"
        self.message = '皜祈岫&#26368;@M?瀢CA6?v肴?X疻?m樖'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei, 'message': self.message})

    def verify_device_lock(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')

        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def teardown(self):

        apiworker = APIRequestWorker('/api/device/unlock')
        apiworker.set_header({'X-Access-Token': self.session_id})
        apiworker.set_data({'imei': self.imei})

        apiworker.post()

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_lock():

            result = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02016:

    '''
    POST /api/device/erase
    Verify device not locked
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.error_msg = "erase_device_service failed !"

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker('/api/device/erase')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei})

    def verify_device_erase(self):

        self.social_oauth_token = self.apiworker.get_social_oauth_token(
            'ya29.Ci-SA_hb0EuIC0jY1BZXdwLeDkNBSi1ea0dy2BcMhD25ZDGWkmSGwrJpdDQD4DpRdw')
        self.apiworker.set_header(
            {'Authorization': 'JWT ' + self.social_oauth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True, r.status_code

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'activated':
                    return True, str(i['service_state'])
        return False, ''

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result == False):
            try:
                if r.json['message'] == self.error_msg:
                    return True, ''
                else:
                    return False, 'MessageError , msg is "{0}" ,not "{1}"'.format(
                        r.json['message'], self.error_msg)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post()

        erase_result = self.verify_device_erase()

        if erase_result[0]:
            result = (
                False,
                'mgmt status error. status info : {0}'.format(
                    erase_result[1]))

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02017:

    '''
    GET /api/file/{inode}/download
    Verify img data (.jpg)
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.data_inode = '10843'
        self.file_name = 'at-here-waiting-for-you.jpg'
        self.file_md5 = '8ac826d1f309895168f881a71c4f356b'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, 'X-Imei': self.imei})

    def teardown(self):

        self.mongowkrker.del_session_id()

        if os.path.isfile(self.file_name):
            os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:

            result, download_files_md5 = self.terafonn_web_server.generate_file_md5(self.file_name)

            if result and self.file_md5 == download_files_md5:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02018:

    '''
    GET /api/file/{inode}/download
    Verify audio data (.mp3)
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.data_inode = '9190'
        self.file_name = '天籟之戰 華晨宇《我的滑板鞋2016》.mp3'
        self.file_md5 = '30c045a0e2a5f6700c52611411c96df0'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, 'X-Imei': self.imei})

    def teardown(self):

        self.mongowkrker.del_session_id()

        if os.path.isfile(self.file_name):
            os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:

            result, download_files_md5 = self.terafonn_web_server.generate_file_md5(self.file_name)

            if result and self.file_md5 == download_files_md5:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02019:

    '''
    GET /api/file/{inode}/download
    Verify video data (.mp4)
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.data_inode = '4019'
        self.file_name = '我的滑板鞋_2.mp4'
        self.file_md5 = 'eff16b6afbf1ffe97abd4c718f560d11'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, 'X-Imei': self.imei})

    def teardown(self):

        self.mongowkrker.del_session_id()

        if os.path.isfile(self.file_name):
            os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:

            result, download_files_md5 = self.terafonn_web_server.generate_file_md5(self.file_name)

            if result and self.file_md5 == download_files_md5:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02020:

    '''
    GET /api/file/{inode}/download
    Verify video data (.zip)
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.data_inode = '9064'
        self.file_name = 'Selenium2Library-master.zip'
        self.file_md5 = 'a81174c823c733324432f0a7ad22ef04'

        self.session_id = self.mongowkrker.inert_session_id()
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, 'X-Imei': self.imei})

    def teardown(self):

        self.mongowkrker.del_session_id()

        if os.path.isfile(self.file_name):
            os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:

            result, download_files_md5 = self.terafonn_web_server.generate_file_md5(self.file_name)

            if result and self.file_md5 == download_files_md5:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02021:

    '''
    PUT /api/webdav/
    Verify new password less 6 characters
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182984"
        self.new_password = 'Aa'
        self.error_msg = 'invalid input !'

        self.session_id = self.mongowkrker.inert_session_id()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data(
            {'imei': self.imei, 'new_password': self.new_password})

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result is False):
            try:
                if r.json['message'] == self.error_msg:
                    return True, ''
                else:
                    return False, 'MessageError , msg is "{0}" ,not "{1}"'.format(
                        r.json['message'], self.error_msg)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.put()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02022:

    '''
    PUT /api/webdav/
    Verify change password (orgin password is wrong)
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182984"
        self.origin_password = 'test02031'
        self.wrong_orgin = 'test02031wrogin'
        self.new_password = 'Aa123456'
        self.error_msg = 'password is incorrect !'

        self.session_id = self.mongowkrker.inert_session_id()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei,
                                 'origin_password': self.wrong_orgin,
                                 'new_password': self.new_password})

    def setup(self):

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.origin_password})
        apiworker_setup.put()

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result is False):
            try:
                if r.json['message'] == self.error_msg:
                    return True, ''
                else:
                    return False, 'MessageError , msg is "{0}" ,not "{1}"'.format(
                        r.json['message'], self.error_msg)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.put()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02023:

    '''
    PUT /api/webdav/
    Verify change password (orgin password is right)
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182985"
        self.origin_password = 'Aa123456'
        self.new_password = '123456Aa'

        self.session_id = self.mongowkrker.inert_session_id()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header({'X-Access-Token': self.session_id})
        self.apiworker.set_data({'imei': self.imei,
                                 'origin_password': self.origin_password,
                                 'new_password': self.new_password})

    def setup(self):

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.origin_password})
        apiworker_setup.put()

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        return (
            True, '') if r.result is True else (
            False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.put()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02024:

    '''
    POST /api/feedback/
    Verity missing required parameter (name)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                "tera_phone",
                "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.msg = 'missing or invalid feedback["name"]'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name, self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02025:

    '''
    POST /api/feedback/
    Verity missing required parameter (email)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.msg = 'missing or invalid feedback["email"]'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name, self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02026:

    '''
    POST /api/feedback/
    Verity missing required parameter (phone)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.msg = 'missing or invalid feedback["phone"]'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name, self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02027:

    '''
    POST /api/feedback/
    Verity missing required parameter (origin_of_issue)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.msg = 'missing or invalid feedback["origin_of_issue"]'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name, self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02028:

    '''
    POST /api/feedback/
    Verity missing required parameter (category)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.msg = 'missing or invalid feedback["category"]'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name, self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02029:

    '''
    POST /api/feedback/
    Verity missing required parameter (description)
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect"}

        self.msg = 'missing or invalid feedback["description"]'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name, self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02030:

    '''
    POST /api/feedback/
    Verity missing required attachment file
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.msg = 'missing or invalid attachments'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(meta=self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['name'] == self.meta['name'] and r.json['email'] == self.meta['email'] and r.json['phone'] == self.meta['phone'] and r.json['origin_of_issue'] == self.meta['origin_of_issue'] and r.json[
                        'device_model'] == self.meta['device_model'] and r.json['web_browser'] == self.meta['web_browser'] and r.json['category'] == self.meta['category'] and r.json['description'].encode('utf-8') == self.meta['description']:
                    return True, ''
                else:
                    return False, 'meta contents not same, response contents:{0}'.format(
                        r.json)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02031:

    '''
    POST /api/feedback/
    Verity missing required attachment file
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = '17m'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.msg = 'BSON document too large (17825973 bytes) - the connected server supports BSON document sizes up to 16793598 bytes.'

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name,self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and r.result == False:
            try:
                if r.json['message'] == self.msg:
                    return True, ''
                else:
                    return False, 'error msg wrong, current msg:{0}'.format(r.json[
                                                                            'message'])
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02032:

    '''
    POST /api/feedback/
    Verity attachment file format is *.png
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'web_mytera_screenshot.png'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name,self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['attachments'] and r.json['name'] == self.meta['name'] and r.json['email'] == self.meta['email'] and r.json['phone'] == self.meta['phone'] and r.json['origin_of_issue'] == self.meta['origin_of_issue'] and r.json[
                        'device_model'] == self.meta['device_model'] and r.json['web_browser'] == self.meta['web_browser'] and r.json['category'] == self.meta['category'] and r.json['description'].encode('utf-8') == self.meta['description']:
                    return True, ''
                else:
                    return False, 'meta contents not same, response contents:{0}'.format(
                        r.json)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02033:

    '''
    POST /api/feedback/
    Verity attachment file format is *.log
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.py'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name,self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['attachments'] and r.json['name'] == self.meta['name'] and r.json['email'] == self.meta['email'] and r.json['phone'] == self.meta['phone'] and r.json['origin_of_issue'] == self.meta['origin_of_issue'] and r.json[
                        'device_model'] == self.meta['device_model'] and r.json['web_browser'] == self.meta['web_browser'] and r.json['category'] == self.meta['category'] and r.json['description'].encode('utf-8') == self.meta['description']:
                    return True, ''
                else:
                    return False, 'meta contents not same, response contents:{0}'.format(
                        r.json)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02034:

    '''
    POST /api/feedback/
    Verity attachment file format is *.zip
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = 'feedback.zip'
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name,self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['attachments'] and r.json['name'] == self.meta['name'] and r.json['email'] == self.meta['email'] and r.json['phone'] == self.meta['phone'] and r.json['origin_of_issue'] == self.meta['origin_of_issue'] and r.json[
                        'device_model'] == self.meta['device_model'] and r.json['web_browser'] == self.meta['web_browser'] and r.json['category'] == self.meta['category'] and r.json['description'].encode('utf-8') == self.meta['description']:
                    return True, ''
                else:
                    return False, 'meta contents not same, response contents:{0}'.format(
                        r.json)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02035:

    '''
    POST /api/feedback/
    Verity attachment file is multiple files
    '''

    def __init__(self):

        self.mongowkrker = MongodbWorker()

        self.attachments_name = ['feedback.zip','folder_screenshot.png']
        self.meta = {
            "name": "Allen Wayne",
            "email": "allen.wayne_02108@gmail.com",
            "phone": "0937123223",
            "origin_of_issue": [
                    "tera_phone",
                    "tera_web"],
            "device_model": "LG Nexus 5X",
            "web_browser": {
                "name": "Google Chrome",
                "version": "52.0.2743.116",
                "os": "windows"},
            "category": "defect",
            "description": "我的手機在 Rest 後無法 bla bla bla.."}

        self.session_id = self.mongowkrker.inert_session_id()

        self.apiworker = APIRequestWorker('/api/feedback')
        self.apiworker.set_header(
            {'X-Access-Token': self.session_id, "X-Auth-Type": "code"})
        self.apiworker.set_files(self.attachments_name,self.meta)

    def teardown(self):

        self.mongowkrker.del_session_id()

    def parse_response(self, r):

        if r.json and (r.result):
            try:
                if r.json['attachments'] and r.json['name'] == self.meta['name'] and r.json['email'] == self.meta['email'] and r.json['phone'] == self.meta['phone'] and r.json['origin_of_issue'] == self.meta['origin_of_issue'] and r.json[
                        'device_model'] == self.meta['device_model'] and r.json['web_browser'] == self.meta['web_browser'] and r.json['category'] == self.meta['category'] and r.json['description'].encode('utf-8') == self.meta['description']:
                    return True, ''
                else:
                    return False, 'meta contents not same, response contents:{0}'.format(
                        r.json)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.post_files()

        self.teardown()

        return self.parse_response(r)

'''
Webdav Test
'''


class TeraClientServer_03001:

    '''
    PRPPFIND
    Verify list
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.new_password = 'Aa123456'
        self.tester_name = 'Tester@gmail.com'

        self.verify_file_list = ['Alarms', 'Android', 'DCIM', 'Download', 'hbtupdater', 'Movies', 'Music', 'Notifications', 'Pictures', 'Podcasts', 'Ringtones', '%E5%A3%93%E7%B8%AE%E6%AA%94', '%E5%A4%9A%E6%AA%94%E6%A1%88', '%E5%A4%A7%E6%AA%94%E6%A1%88', '%E6%96%87%E4%BB%B6', '%E8%AA%9E%E7%B3%BB']

        self.session_id = self.mongowkrker.inert_session_id()

    def setup(self):

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        apiworker_setup.put()

        apiworker_setup = APIRequestWorker('/api/webdav/enable')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data({'imei': self.imei})
        apiworker_setup.post()

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id, 'X-Imei': self.imei})
        
        self.url = apiworker_setup.get().json['url']
      
    def parse_result(self,webdav_result):

        files_name = []
        try:
            name_tmp = re.findall('<d:href>(.+?)</d:href>', webdav_result)
            for i in name_tmp[1:]:
                str_i = i.replace(str(name_tmp[0]),'')
                files_name.append(str_i)
            
            if files_name:
                if files_name == sorted(self.verify_file_list):
                    return True,''
                else:
                    return False,'file lists error, return is :{0}'.format(files_name)
            else:
                return False,'filter error, return is :{0}'.format(webdav_result)

        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        

    def verify_list(self):

        url="{0}/".format(self.url)

        cmd = 'curl -i -H "Depth: 1" -u {0}:{1} -X PROPFIND {2}'.format(self.tester_name,self.new_password,url)

        r = os.popen(cmd).read()

        return self.parse_result(r)

        
    def run(self):

        self.setup()

        return self.verify_list()

class TeraClientServer_03002:

    '''
    PRPPFIND
    Verify sub list
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.new_password = 'Aa123456'
        self.tester_name = 'Tester@gmail.com'

        self.verify_file_list = ['%E9%9F%B3%E6%A8%82']

        self.session_id = self.mongowkrker.inert_session_id()

    def setup(self):

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        apiworker_setup.put()

        apiworker_setup = APIRequestWorker('/api/webdav/enable')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data({'imei': self.imei})
        apiworker_setup.post()

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id, 'X-Imei': self.imei})
        
        self.url = apiworker_setup.get().json['url']
      
    def parse_result(self,webdav_result):

        files_name = []
        try:
            name_tmp = re.findall('<d:href>(.+?)</d:href>', webdav_result)
            for i in name_tmp[1:]:
                str_i = i.replace(str(name_tmp[0]),'')
                files_name.append(str_i)
            
            if files_name:
                if files_name == sorted(self.verify_file_list):
                    return True,''
                else:
                    return False,'file lists error, return is :{0}'.format(files_name)
            else:
                return False,'filter error, return is :{0}'.format(webdav_result)

        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        

    def verify_list(self):

        url="{0}/Music".format(self.url)

        cmd = 'curl -i -H "Depth: 1" -u {0}:{1} -X PROPFIND {2}'.format(self.tester_name,self.new_password,url)

        r = os.popen(cmd).read()

        return self.parse_result(r)

        
    def run(self):

        self.setup()

        return self.verify_list()


class TeraClientServer_03003:

    '''
    GET
    Verify download files
    '''

    def __init__(self):

        self.terafonn_web_server = InitTerafonnWebServer()
        self.mongowkrker = MongodbWorker()

        self.imei = "353627076182982"
        self.new_password = 'Aa123456'
        self.tester_name = 'Tester@gmail.com'

        self.file_name = 'eng.jpg'
        self.file_md5 = '5dcc0c76b05149ea96c119ebad8239f3'
        self.session_id = self.mongowkrker.inert_session_id()

    def setup(self):

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        apiworker_setup.put()

        apiworker_setup = APIRequestWorker('/api/webdav/enable')
        apiworker_setup.set_header({'X-Access-Token': self.session_id})
        apiworker_setup.set_data({'imei': self.imei})
        apiworker_setup.post()

        apiworker_setup = APIRequestWorker('/api/webdav/')
        apiworker_setup.set_header({'X-Access-Token': self.session_id, 'X-Imei': self.imei})
        
        self.url = apiworker_setup.get().json['url']
      
    def parse_result(self,webdav_result):

        try:
            result, download_files_md5 = self.terafonn_web_server.generate_file_md5(self.file_name)
            if result and self.file_md5 == download_files_md5:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)


    def verify_download(self):

        url="{0}/Pictures/%E5%9C%96%E7%89%87/jpg/{1}".format(self.url,self.file_name)

        cmd = 'curl -k -H "Depth: 1" -u {0}:{1} {2} > ./{3}'.format(self.tester_name,self.new_password,url,self.file_name)

        r = os.popen(cmd).read()

        return self.parse_result(r)

        
    def run(self):

        self.setup()

        return self.verify_download()


'''
Meta Parse Test
'''

class TeraClientServer_05001:

    '''
    Verify parse list volume - old version meta
    '''

    def __init__(self):

        self.meta_type = 'old'
        self.meta = 'FSmgr_backup'
        self.function_name = 'list_vols'
        self.verify_file_list = [(2, 1, 'hcfs_data'), (3, 1, 'hcfs_app'), (148, 3, 'hcfs_external')]

    def list_vols(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()

        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.verify_file_list == sorted(result):
                return (True, '')
            else:
                return (False, 'Parse content error , msg:{0}'.format(sorted(result)))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.list_vols()


        return self.parse_result(result)

class TeraClientServer_05002:

    '''
    Verify parse list volume - new version meta
    '''

    def __init__(self):

        self.meta_type = 'new'
        self.meta = 'FSmgr_backup'
        self.function_name = 'list_vols'
        self.verify_file_list = [(2, 1, 'hcfs_data'), (3, 1, 'hcfs_app'), (140, 3, 'hcfs_external')]

    def list_vols(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()
        
        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.verify_file_list == sorted(result):
                return (True, '')
            else:
                return (False, 'Parse content error , msg:{0}'.format(sorted(result)))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.list_vols()

        return self.parse_result(result)

class TeraClientServer_05003:

    '''
    Verify parse meta - old version meta
    '''

    def __init__(self):

        self.meta_type = 'old'
        self.meta = 'meta_151'
        self.function_name = 'parse_meta'
        self.meta_key_list = ['child_number', 'file_type', 'result', 'stat']
        self.meta_value_list = [0, 0, 13, {'size': 0, 'metaver': 1, 'magic': [104, 99, 102, 115], 'ctime': 27232, 'nlink': 13, 'mtime_nsec': 0, 'rdev': 0, 'blocks': 0, 'dev': 0, '__pad1': 0, 'blksize': 4096, 'ino': 151, 'mode': 16877, 'atime_nsec': 0, 'mtime': 27232, 'ctime_nsec': 0, 'gid': 0, 'atime': 1481532886, 'uid': 0}]
        
    def parse_meta(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()
        
        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.meta_key_list == sorted(result.keys()) and self.meta_value_list == sorted(result.values()):
                return (True, '')
            else:
                return (False, 'Parse content error , key:{0} ; value:{1}'.format(sorted(result.keys()),sorted(result.values())))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.parse_meta()
        
        return self.parse_result(result)

class TeraClientServer_05004:

    '''
    Verify parse meta - new version meta
    '''

    def __init__(self):

        self.meta_type = 'new'
        self.meta = 'meta_203'
        self.function_name = 'parse_meta'
        self.meta_key_list = ['child_number', 'file_type', 'result', 'stat']
        self.meta_value_list = [0, 0, 2, {'metaver': 1, 'blocks': 0, 'uid': 10008, 'nlink': 2, 'mtime_nsec': 0, 'rdev': 0, 'dev': 0, 'ctime': 611903, '__pad1': 0, 'blksize': 4096, 'gid': 10008, 'mode': 16832, 'atime_nsec': 0, 'mtime': 611903, 'ctime_nsec': 0, 'magic': [104, 99, 102, 115], 'atime': 1478074873, 'ino': 203, 'size': 0}]
  
    def parse_meta(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()
        
        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.meta_key_list == sorted(result.keys()) and self.meta_value_list == sorted(result.values()):
                return (True, '')
            else:
                return (False, 'Parse content error  , key:{0} ; value:{1}'.format(sorted(result.keys()),sorted(result.values())))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.parse_meta()
        
        return self.parse_result(result)

class TeraClientServer_05005:

    '''
    Verify parse childs - old version meta
    '''

    def __init__(self):

        self.meta_type = 'old'
        self.meta = 'meta_151'
        self.function_name = 'parse_childs'
        self.meta_key_list = ['child_list', 'num_child_walked', 'offset', 'result']
        self.meta_value_list = [0, 13, [{'d_name': '.', 'inode': 151, 'd_type': 0}, {'d_name': '..', 'inode': 148, 'd_type': 0}, {'d_name': 'Alarms', 'inode': 214, 'd_type': 0}, {'d_name': 'Android', 'inode': 1079, 'd_type': 0}, {'d_name': 'DCIM', 'inode': 227, 'd_type': 0}, {'d_name': 'Download', 'inode': 226, 'd_type': 0}, {'d_name': 'hbtupdater', 'inode': 154, 'd_type': 0}, {'d_name': 'Movies', 'inode': 225, 'd_type': 0}, {'d_name': 'Music', 'inode': 205, 'd_type': 0}, {'d_name': 'Notifications', 'inode': 220, 'd_type': 0}, {'d_name': 'Pictures', 'inode': 224, 'd_type': 0}, {'d_name': 'Podcasts', 'inode': 207, 'd_type': 0}, {'d_name': 'Ringtones', 'inode': 210, 'd_type': 0}], (289, 13)]
    
    def parse_childs(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()
        
        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.meta_key_list == sorted(result.keys()) and self.meta_value_list == sorted(result.values()):
                return (True, '')
            else:
                return (False, 'Parse content error  , key:{0} ; value:{1}'.format(sorted(result.keys()),sorted(result.values())))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.parse_childs()
        
        return self.parse_result(result)

class TeraClientServer_05006:

    '''
    Verify parse childs - new version meta
    '''

    def __init__(self):

        self.meta_type = 'new'
        self.meta = 'meta_203'
        self.function_name = 'parse_childs'
        self.meta_key_list = ['child_list', 'num_child_walked', 'offset', 'result']
        self.meta_value_list = [0, 2, [{'d_name': '.', 'inode': 203, 'd_type': 0}, {'d_name': '..', 'inode': 149, 'd_type': 0}], (289, 2)]

    def parse_childs(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()
        
        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.meta_key_list == sorted(result.keys()) and self.meta_value_list == sorted(result.values()):
                return (True, '')
            else:
                return (False, 'Parse content error  , key:{0} ; value:{1}'.format(sorted(result.keys()),sorted(result.values())))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.parse_childs()
        
        return self.parse_result(result)

class TeraClientServer_05007:

    '''
    Verify parse list file blocks - old version meta
    '''

    def __init__(self):

        self.meta_type = 'old'
        self.meta = 'meta_2193'
        self.function_name = 'list_file_blocks'
        self.meta_key_list = ['block_list', 'result', 'ret_num']
        self.meta_value_list = [0, 1, ['data_2193_0_1']]
        
    def list_file_blocks(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()
        
        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.meta_key_list == sorted(result.keys()) and self.meta_value_list == sorted(result.values()):
                return (True, '')
            else:
                return (False, 'Parse content error  , key:{0} ; value:{1}'.format(sorted(result.keys()),sorted(result.values())))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.list_file_blocks()
        
        return self.parse_result(result)

class TeraClientServer_05008:

    '''
    Verify parse list file blocks - new version meta
    '''

    def __init__(self):

        self.meta_type = 'new'
        self.meta = 'meta_9095'
        self.function_name = 'list_file_blocks'
        self.meta_key_list = ['block_list', 'result', 'ret_num']
        self.meta_value_list = [0, 1, ['data_9095_0_1']]
        
    def list_file_blocks(self):

        cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,self.meta,self.function_name)

        result = os.popen(cmd).read()
        
        return ast.literal_eval(result)

    def parse_result(self,result):

        try:
            
            if result and self.meta_key_list == sorted(result.keys()) and self.meta_value_list == sorted(result.values()):
                return (True, '')
            else:
                return (False, 'Parse content error  , key:{0} ; value:{1}'.format(sorted(result.keys()),sorted(result.values())))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.list_file_blocks()
        
        return self.parse_result(result)

class TeraClientServer_05009:

    '''
    Verify parse vol usage - old version meta
    '''

    def __init__(self):

        self.meta_type = 'old'
        self.meta = ['FSstat2','FSstat3','FSstat148']
        self.function_name = 'parse_vol_usage'
        self.verify_file_list = [{'usage': 794268, 'result': 0}, {'usage': 118029506, 'result': 0}, {'usage': 196118754, 'result': 0}]

    def parse_vol_usage(self):

        result_list = []

        for i in self.meta:

            cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,i,self.function_name)

            result = os.popen(cmd).read()

            result_list.append(ast.literal_eval(result))
        
        return result_list

    def parse_result(self,result):

        try:
            
            if result and self.verify_file_list == sorted(result):
                return (True, '')
            else:
                return (False, 'Parse content error , msg:{0}'.format(sorted(result)))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.parse_vol_usage()
        
        return self.parse_result(result)


class TeraClientServer_05010:

    '''
    Verify parse vol usage - new version meta
    '''

    def __init__(self):

        self.meta_type = 'new'
        self.meta = ['FSstat2','FSstat3','FSstat140']
        self.function_name = 'parse_vol_usage'
        self.verify_file_list = [{'usage': 72204503, 'result': 0}, {'usage': 375128997, 'result': 0}, {'usage': 14124683574, 'result': 0}]
        
    def parse_vol_usage(self):

        result_list = []

        for i in self.meta:

            cmd = 'python3 {0}/Parse_Meta.py {1} {2} {3}'.format(CURRENT_FILE_PATH,self.meta_type,i,self.function_name)

            result = os.popen(cmd).read()

            result_list.append(ast.literal_eval(result))
        
        return result_list

    def parse_result(self,result):

        try:
            
            if result and self.verify_file_list == sorted(result):
                return (True, '')
            else:
                return (False, 'Parse content error , msg:{0}'.format(sorted(result)))
        except Exception as e:
            return False, 'Exception , msg:{0}'.format(e)
        
    def run(self):

        result = self.parse_vol_usage()
        
        return self.parse_result(result)

class TeraClientServer_99999:

    '''
    clearn environment
    '''

    def __init__(self):
        self.terafonn_web_server = InitTerafonnWebServer()

    def run(self):

        # kill server
        # self.terafonn_web_server.kill_Terafonn_Web_Server()
        # self.terafonn_web_server.kill_fake_arkflex_server()
        # self.terafonn_web_server.kill_fake_swfit_server()

        return (True, '')

if __name__ == '__main__':
    pass
    # terafonn_web_server = InitTerafonnWebServer()
    # terafonn_web_server.launch_Terafonn_Web_Server()
    # time.sleep(20)
    # terafonn_web_server.kill_Terafonn_Web_Server()
