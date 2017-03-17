# -*- coding: utf-8 -*-
import pdb
import os
import traceback
import subprocess
import time
import re
import json
from subprocess import PIPE

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests.packages.urllib3

import config as CONFIG
import hb_crypt

# Ignore warning
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
            if (db_check and
                    len(db_check) < 4):

                return (0, 'Inode not exist')
            else:
                return (1, 'Inode exist')
        except NameError as e:
            return (2, 'Can\'t connect to any DB')
        except Exception as e:
            return (3, 'Check inode error , msg:{0}'.format(str(e)))

    def check_file_md5(self, file_name):

        # check files exist
        if not os.path.isfile(file_name):
            return (False, str(file_name) + ' not exist')

        command = 'md5sum ' + str(file_name)
        command_result = os.popen(command).read().split(file_name)[0].strip()

        return True, command_result


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
        # print p
        if len(command_result) < 3:

            return (False, 'Inode not exist')
        else:
            return (True, 'Inode exist')


class SeleniumWorker(object):

    """
    Provide realted functions for selenium action
    """

    def __init__(self):

        self.display = Display(visible=0, size=(800, 600))
        self.display.start()
        # self.driver = webdriver.Chrome()
        self.driver = webdriver.PhantomJS()
        self.driver = webdriver.Firefox()

    def google_login(self, url):

        try:

            # Google sigin
            self.driver.get(url)

            element = WebDriverWait(
                self.driver, 30).until(
                EC.presence_of_element_located(
                    (By.ID, "Email")))
            self.driver.find_element_by_id(
                'Email').send_keys(CONFIG.Test_Email)
            self.driver.find_element_by_name('signIn').click()

            element = WebDriverWait(
                self.driver, 30).until(
                EC.presence_of_element_located(
                    (By.ID, "Passwd")))
            self.driver.find_element_by_id(
                'Passwd').send_keys(CONFIG.Test_Password)
            self.driver.find_element_by_id('signIn').click()

            time.sleep(5)   # magic sleep
            element = WebDriverWait(
                self.driver, 10).until(
                EC.element_to_be_clickable(
                    (By.ID, 'submit_approve_access')))
            self.driver.find_element_by_id('submit_approve_access').click()
            time.sleep(5)   # magic sleep

            current_url = self.driver.current_url

            self.driver.close()
            self.display.stop()

            return current_url

        except Exception as e:
            return traceback.print_exc()

    def take_gauth_token(self):

        try:

            # Launcher controller server
            self.terafonn_web_server = InitTerafonnWebServer()
            self.terafonn_web_server.Launch_Controller_Server()

            driver = self.driver

            # fake Google sigin
            driver.get(CONFIG.FAKE_CONTROLLER_SERVER_URL)

            elem = driver.find_element_by_class_name(
                'abcRioButtonIcon').click()
            time.sleep(5)   # magic sleep

            handles = driver.window_handles

            for handle in handles:
                driver.switch_to_window(handle)
                if re.search('Google', driver.title):
                    popup_handle = handle
                else:
                    origin_handle = handle

            # Handle in popup window
            driver.switch_to_window(popup_handle)
            element = WebDriverWait(
                driver, 30).until(
                EC.presence_of_element_located(
                    (By.ID, "Email")))
            driver.find_element_by_id('Email').send_keys(
                'hopebaytest1@gmail.com')
            driver.find_element_by_name('signIn').click()

            element = WebDriverWait(
                driver, 30).until(
                EC.presence_of_element_located(
                    (By.ID, "Passwd")))
            driver.find_element_by_id('Passwd').send_keys('4nXiC9X6')
            driver.find_element_by_id('signIn').click()

            time.sleep(5)   # magic sleep
            if len(driver.window_handles) == 2:
                element = WebDriverWait(
                    driver, 10).until(
                    EC.element_to_be_clickable(
                        (By.ID, 'submit_approve_access')))
                driver.find_element_by_id('submit_approve_access').click()
                time.sleep(5)   # magic sleep

            driver.switch_to_window(origin_handle)
            element = WebDriverWait(
                driver, 30).until(
                EC.presence_of_element_located(
                    (By.ID, "token")))
            token = driver.find_element_by_id('token').text
            access_token = driver.find_element_by_id('access_token').text
            driver.close()

            # kill server
            self.terafonn_web_server.kill_Controller_Server()

            result = {'token': token, 'access_token': access_token}

            return result if token else None

        except Exception as e:
            return traceback.print_exc()


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

            if (resp_data and resp_data['imei'] == [
                    'Device with this imei already exists.']):
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
            # headers=self.headers,
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

        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.apiworker = APIRequestWorker()
        self.auth_token = self.apiworker.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker.set_header(self.api_headers)

    def run(self):

        # Launch Server
        # self.terafonn_web_server.Launch_Terafonn_Web_Server()
        # self.terafonn_web_server.kill_docker('env_frontend-dev_1')
        self.terafonn_web_server.launch_fake_swfit_server()
        self.terafonn_web_server.launch_fake_arkflex_server()
        self.terafonn_web_server.patch_gauth_client()
        # self.terafonn_web_server.restore_gauth_client()

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

        return (True, '')

'''
TeraClient - Server API
'''


class TeraClientServer_01001:

    '''
    GET /auth/google
    '''

    def __init__(self):

        self.url = CONFIG.TERA_CLIENT_HOST_URL + '/auth/google'
        self.selenium_worker = SeleniumWorker()

    def parse_response(self, r):

        if r == CONFIG.TERA_CLIENT_HOST_URL + '/devices':
            return (True, '')

        else:
            return (False, r)

    def run(self):
        result = self.selenium_worker.google_login(self.url)
        return self.parse_response(result)


class TeraClientServer_01002:

    '''
    POST /api/login
    '''

    def __init__(self):

        self.gauth_toekn = 'hopebaytest1@gmail.com'
        self.apiworker = APIRequestWorker('/api/login')
        self.apiworker.set_data({'access_token': str(self.gauth_toekn)})
        self.apiworker.set_header(None)

    def parse_response(self, r):

        if r.json and r.result is True:

            try:
                if (r.json['username'] == self.gauth_toekn and
                        r.json['token'] and r.json['user_id']):
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

        r = self.apiworker.post()
        return self.parse_response(r)


class TeraClientServer_01003:

    '''
    GET /api/devices
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.imei = "110030100301003"

        self.available_activation_code = self.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/devices')
        self.auth_token = self.apiworker.get_social_oauth_token(
            'test01003@hopebaytech.com')
        # self.apiworker.set_header({'X-Access-Token': self.auth_token})
        self.apiworker.set_header(
            {'X-Access-Token': 'test01003@hopebaytech.com'})

    def get_available_activation_code(self):

        # init - admin info
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        # get available activation code by admin
        self.auth_token_admin = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token_admin,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)

        t = self.apiworker_admin.get_available_activation_code()

        return t

    def create_new_devices(self):

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.MODEL = self.apiworker_admin.query_model().json()[0]['id']

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.available_activation_code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "6.0.1",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if r.json['devices'] and len(r.json['devices']) == 1:
                    for device_i in r.json['devices']:
                        if device_i.keys() == [
                                u'status',
                                u'total_space',
                                u'name',
                                u'expiration_date',
                                u'registration_date',
                                u'webdav_state',
                                u'imei',
                                u'used_space',
                                u'service_state']:
                            return True, ''
                        else:
                            return False, 'devices key error, msg:{0}'.format(
                                device_i.keys())
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

        self.create_new_devices()

        r = self.apiworker.get()

        return self.parse_response(r)


class TeraClientServer_01004:

    '''
    GET /api/files

    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010040100401004"
        self.start = 0
        self.length = 20
        self.files = 1
        self.recordsTotal = 1

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.auth_token = self.apiworker.get_social_oauth_token(
            'test01004@hopebaytech.com')
        self.apiworker.set_header(
            {'X-Access-Token': 'test01004@hopebaytech.com'})

        self.currentPath = {
            "inode": 203,
            "name": "DCIM",

        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            'test01004@hopebaytech.com')

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:

            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length and
                        r.json['currentPath'] == self.currentPath):
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

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_01005:

    '''
    GET /api/system_logs
    '''

    def __init__(self):
        pass

    def run(self):
        return False, 'Testcase is not implemented'


class TeraClientServer_01006:

    '''
    POST /api/device/lock
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '010060100601006'
        self.tester_mail = 'test01006@hopebaytech.com'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker.set_data({'imei': self.imei})

    def verify_device_lock(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def setup(self):

        # creat device
        self.create_device()

        # restore lock header
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})

    def teardown(self):

        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

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


class TeraClientServer_01007:

    '''
    POST /api/device/unlock
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '010070100701007'
        self.tester_mail = 'test01007@hopebaytech.com'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # locked devices
        self.apiworker = APIRequestWorker('/api/device/unlock')
        self.apiworker.set_data({'imei': self.imei})

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def verify_device_unlock(self):

        self.auth_token = self.apiworker.get_auth_token()
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:

                if str(i['service_state']) != 'activated':
                    return True
        return False

    def setup(self):

        # creat device
        self.create_device()

        # restore apiworker header
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})

        # lock deivice
        self.lock_worker = APIRequestWorker('/api/device/lock')
        self.lock_worker.set_header({'X-Access-Token': self.tester_mail})
        self.lock_worker.set_data({'imei': self.imei})

        self.lock_worker.post()

    def teardown(self):
        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

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


class TeraClientServer_01008:

    '''
    POST /api/transfer_data
    '''

    def __init__(self):
        pass

    def run(self):
        return False, 'Testcase is not implemented'


class TeraClientServer_01009:

    '''
    POST /api/device/erase
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '010090100901009'
        self.tester_mail = 'test01009@hopebaytech.com'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # locked devices
        self.apiworker = APIRequestWorker('/api/device/erase')
        self.apiworker.set_data({'imei': self.imei})

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def verify_device_unlock(self):

        self.auth_token = self.apiworker.get_auth_token()
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:

                if str(i['service_state']) != 'activated':
                    return True
        return False

    def setup(self):

        # creat device
        self.create_device()

        # restore apiworker header
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})

        # lock deivice
        self.lock_worker = APIRequestWorker('/api/device/lock')
        self.lock_worker.set_header({'X-Access-Token': self.tester_mail})
        self.lock_worker.set_data({'imei': self.imei})

        self.lock_worker.post()

    def teardown(self):
        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        return True, '' if r.result else (False, (r.status_code, r.text))

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

        self.teardown()

        return result


class TeraClientServer_01010:

    '''
    GET /api/file/{inode}/download
    Verify doc text data (.txt)
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010100101001010"
        self.social_auth = 'test01010@hopebaytech.com'
        self.data_inode = '9282'
        self.file_name = 'test_data.txt'
        self.file_md5 = '521ef13d6c95fce5678683c463540be3'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        # self.expire_token = None
        self.apiworker.set_header(
            {'X-Access-Token': self.social_auth, 'X-Imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def teardown(self):
        # clean files

        os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:
            # check md5
            result = self.terafonn_web_server.check_file_md5(self.file_name)

            if result and self.file_md5 == result[1]:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        self.setup()

        self.create_new_devices()

        # r = self.apiworker.get()
        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_01011:

    '''
    GET /api/files/{inode}/info
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010110101101011"
        self.social_auth = 'test01011@hopebaytech.com'
        self.meta_inode = '9285'
        self.size = 50432714

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.meta_inode + '/info')

        # self.expire_token = None
        self.apiworker.set_header(
            {'X-Access-Token': self.social_auth, 'X-Imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['a_time'] and
                        r.json['c_time'] and
                        r.json['m_time'] and
                        r.json['size'] == self.size):
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

        self.setup()

        self.create_new_devices()

        r = self.apiworker.get()

        return self.parse_response(r)


class TeraClientServer_01012:

    '''
    POST /api/webdav/enable
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010120101201012"
        self.social_auth = 'test01012@hopebaytech.com'
        self.new_password = 'Aa123456'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/enable')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data({'imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_01013:

    '''
    POST /api/webdav/disable
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010130101301013"
        self.social_auth = 'test01013@hopebaytech.com'
        self.new_password = 'Aa123456'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/disable')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data({'imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

        # Enable webdav
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_01014:

    '''
    PUT /api/webdav/
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010140101401014"
        self.social_auth = 'test01014@hopebaytech.com'
        self.new_password = 'Aa123456'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data({'imei': self.imei,
                                 'new_password': self.new_password})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        return (True, '') if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.put()

        return self.parse_response(r)


class TeraClientServer_01015:

    '''
    GET /api/webdav/
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010150101501015"
        self.social_auth = 'test01015@hopebaytech.com'
        self.new_password = 'Aa123456'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header(
            {'X-Access-Token': self.social_auth, 'X-Imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

        # Enable webdav
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['url'] and
                        r.json['username'] == self.social_auth):
                    return True, ''
                else:
                    return False, 'Username Error , username is {0},not {1}'.format(
                        r.json['username'], self.social_auth)
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

'''
Integration Test
'''


class TeraClientServer_02001:

    '''
    GET /api/devices
    Verify arkflex expire token
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.imei = "020010200102001"
        self.error_msg = 'token expired !'

        self.available_activation_code = self.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/devices')

        self.auth_token = 'test02001@hopebaytech.com'
        self.apiworker.set_header({'X-Access-Token': self.auth_token})

    def get_available_activation_code(self):

        # init - admin info
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

       # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        return self.code

    def create_new_devices(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            'test01010@hopebaytech.com')

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def teardown(self):

        self.terafonn_web_server.patch_gauth_client()

    def parse_response(self, r):

        if r.json and r.result is False:
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

        self.create_new_devices()

        self.apiworker.set_header(
            {'X-Access-Token': 'expire_token@hopebaytech.com'})

        r = self.apiworker.get()

        return self.parse_response(r)


class TeraClientServer_02002:

    '''
    GET /api/devices
    Verify no devices
    '''

    def __init__(self):

        # setup - init
        self.apiworker = APIRequestWorker('/api/devices')
        self.auth_token = 'test02002@hopebaytech.com'
        self.apiworker.set_header({'X-Access-Token': self.auth_token})
        self.devices = []

    def parse_response(self, r):

        if r.json and r.result:
            try:
                if r.json['devices'] == self.devices:
                    return True, ''
                else:
                    return False, 'DevicesError , devices is "{0}" ,not "{1}"'.format(
                        r.json['devices'], self.devices)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        r = self.apiworker.get()

        return self.parse_response(r)


class TeraClientServer_02003:

    '''
    POST /api/files
    Verify arkflex expire token
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020030200302003"
        self.social_auth = 'test02003@hopebaytech.com'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.expire_token = 'expire_token@hopebaytech.com'
        # self.expire_token = None
        self.apiworker.set_header({'X-Access-Token': self.expire_token})

        self.currentPath = {
            "inode": 7759,
            "name": "test_folder",

        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': 0,
                                 'length': 20,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02004:

    '''
    POST /api/files
    Verify params of start over file count
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020040200402004"
        self.social_auth = 'test02004@hopebaytech.com'
        self.start = 4
        self.length = 2
        self.files = []
        self.recordsTotal = 2

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        # auth_token = self.apiworker.get_social_oauth_token(self.social_auth)
        auth_token = self.social_auth
        self.apiworker.set_header({'X-Access-Token': auth_token})

        self.currentPath = {
            "inode": 9284,
            "name": "Camera",

        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user(
            {
                "imei_code": self.imei,
                "activation_code": self.code,
                "force": False,
                "vendor": "HopeBay",
                "model": "test_model",
                "android_version": "1.0.0",
                "HCFS_version": "2.1.1.1234",
                "mgmt_app_version": "1.0.0.1234",
                "launcher_version": "1.0.0.5678"})

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length and
                        r.json['currentPath'] == self.currentPath):
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

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02005:

    '''
    POST /api/files
    Verify mandatory params is none
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020050200502005"
        self.social_auth = 'test02005@hopebaytech.com'
        self.start = 0
        self.length = 20
        self.files = 11
        self.recordsTotal = 11
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/files')

        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.apiworker.set_data({'imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02006:

    '''
    POST /api/files
    Verify mandatory params is null
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020060200602006"
        self.social_auth = 'test02006@hopebaytech.com'
        self.error_msg = 'missing or invalid start format'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        auth_token = self.apiworker.get_social_oauth_token(self.social_auth)
        self.apiworker.set_header({'X-Access-Token': auth_token})

        self.currentPath = {}
        self.apiworker.set_data({'imei': self.imei,
                                 'start': '',
                                 'length': '',
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02007:

    '''
    POST /api/files
    Device is locked
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020070200702007"
        self.social_auth = 'test02007@hopebaytech.com'
        self.start = 0
        self.length = 20
        self.files = 2
        self.recordsTotal = 2
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        # auth_token = self.apiworker.get_social_oauth_token(self.social_auth)
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 9284,
            "name": "Camera"

        }
        self.apiworker.set_data({'imei': self.imei,  # for testing set None
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def lock_device(self):

        self.lock_worker = APIRequestWorker('/api/device/lock')
        auth_token = self.lock_worker.get_social_oauth_token(self.social_auth)
        self.lock_worker.set_header({'X-Access-Token': auth_token})
        self.lock_worker.set_data({'imei': self.imei})
        self.lock_worker.post()

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):
        self.setup()
        self.create_new_devices()
        self.lock_device()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02008:

    '''
    POST /api/files
        Verity current_inode = 0 & one external vol
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020080200802008"
        self.social_auth = 'test02008@hopebaytech.com'
        self.start = 0
        self.length = 20
        self.files = 11
        self.recordsTotal = 11
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')

        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {}
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02009:

    '''
    POST /api/files
        Verity current_inode = 0 & many external vol
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020090200902009"
        self.social_auth = 'test02009@hopebaytech.com'
        self.start = 0
        self.length = 20
        self.files = 11
        self.recordsTotal = 11
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        # auth_token = self.apiworker.get_social_oauth_token(self.social_auth)
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 0,
            "name": "/",
        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02010:

    '''
    POST /api/files
    Verity next inode
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020100201002010"
        self.social_auth = 'test02010@hopebaytech.com'
        self.start = 0
        self.length = 3
        self.files = 1
        self.recordsTotal = 2
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 203,
            "name": "DCIM",
            "next": {"inode": 9284, "name": "Camera"}
        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02011:

    '''
    POST /api/files
    Verity next inode & next inode
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'

        self.imei = "020110201102011"
        self.social_auth = 'test02011@hopebaytech.com'
        self.start = 0
        self.length = 20
        self.files = 2
        self.recordsTotal = 2
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 148,
            "name": "0",
            "next": {
                "inode": 203,
                "name": "DCIM",
                "next": {
                    "inode": 9284,
                    "name": "Camera"
                }
            }
        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
            else:
                return (False, 'keys error')

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02012:

    '''
    POST /api/files
    Verity inode in cache
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()

        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020120201202012"
        self.social_auth = 'test02012@hopebaytech.com'
        self.start = 0
        self.length = 20
        self.files = 2
        self.recordsTotal = 2
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 9284,
            "name": "Camera"
        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        self.apiworker.post()

        # Check inode not in cache
        check_result = self.terafonn_web_server.check_inode_by_mongo(
            self.imei, 9284, 0, 2)
        if check_result[0] == 1:
            r = self.apiworker.post()
            return self.parse_response(r)
        else:
            return (False, check_result[1])


class TeraClientServer_02013:

    '''
    POST /api/files
    Verity inode not in cache
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()

        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020130201302013"
        self.social_auth = 'test02013@hopebaytech.com'
        self.start = 0
        self.length = 4
        self.files = 2
        self.recordsTotal = 2
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 9284,
            "name": "Camera"
        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        # Check inode not in cache
        check_result = self.terafonn_web_server.check_inode_by_mongo(
            self.imei, 9284, 0, 2)
        if check_result[0] == 0:
            r = self.apiworker.post()
            return self.parse_response(r)
        else:
            return (False, check_result[1])


class TeraClientServer_02014:

    '''
    POST /api/files
    Verity cache data less than get files
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()

        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020140201402014"
        self.social_auth = 'test02014@hopebaytech.com'
        self.ino_list = ['203', '9284', '9285', '9286']
        self.start = 0
        self.origin_length = 15
        self.modify_length = 15
        self.files = 2
        self.recordsTotal = 2
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 203,
            "name": "DCIM"
        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.origin_length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.modify_length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)

        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        # save into cache
        self.apiworker.post()

        # Check inode not in cache
        check_result = []
        for i in self.ino_list:
            check_result.append(
                self.terafonn_web_server.check_inode_by_mongo(
                    self.imei, i, 0, 20)[0])

        # check_result: check inode
        # exist(DCIM,Camera,IMG_20160630_090346.jpg,VID_20160630_090351.mp4)
        if check_result == [1, 0, 0, 0]:

            # check cache & fired request
            self.currentPath = {"inode": 9284, "name": "Camera"}
            self.apiworker.set_data({'imei': self.imei,
                                     'start': self.start,
                                     'length': self.modify_length,
                                     'currentPath': self.currentPath})
            r = self.apiworker.post()
            return self.parse_response(r)
        else:
            return (
                False,
                'check result error , result list : ' +
                str(check_result))


class TeraClientServer_02015:

    '''
    POST /api/files
    Verity cache data is old
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()

        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020150201502015"
        self.social_auth = 'test02015@hopebaytech.com'
        self.start = 0
        self.length = 20
        self.files = 3
        self.recordsTotal = 3
        self.files_keys = [u'inode', u'type', u'name', u'offset']

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/files')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})

        self.currentPath = {
            "inode": 198,
            "name": "Pictures"
        }
        self.apiworker.set_data({'imei': self.imei,
                                 'start': self.start,
                                 'length': self.length,
                                 'currentPath': self.currentPath})

    def setup(self):

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:
            try:
                if (r.json['files'] and
                        len(r.json['files']) == self.files and
                        r.json['recordsTotal'] == self.recordsTotal and
                        r.json['start'] == self.start and
                        r.json['length'] == self.length):
                    if sorted(
                            r.json['files'][0].keys()) == sorted(
                            self.files_keys):
                        return True, ''
                    else:
                        return False, 'Files Key Error , key is {0}, not {1}'.format(
                            r.json['files'][0].keys(), self.files_keys)
                else:
                    return False, 'return Value Error , files count  is {0}, not {1} ; start is {2},not {3} ; length is {4} ,not {5}'.format(
                        len(r.json['files']), self.files, r.json['start'], self.start, r.json['length'], self.length)
            except KeyError as e:
                return False, 'KeyError , msg:{0}'.format(e)
            except Exception as e:
                return False, 'Exception , msg:{0}'.format(e)
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        self.create_new_devices()

        # save cache
        self.apiworker.post()

        # Check inode in cache
        check_result = self.terafonn_web_server.check_inode_by_mongo(
            self.imei, 198, 0, 2)
        if check_result[0] == 1:
            r = self.apiworker.post()

            return self.parse_response(r)
        else:
            return (False, 'inode not in cache')


class TeraClientServer_02016:

    '''
    POST /api/device/lock
    Verify expire token
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '020160201602016'
        self.tester_mail = 'test02016@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_data({'imei': self.imei})

    def verify_device_lock(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return False

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def setup(self):
        # creat device
        self.create_device()

        # restore lock header
        self.apiworker.set_header({'X-Access-Token': self.expire_token})

    def teardown(self):

        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        if r.json and r.result is False:
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

        r = self.apiworker.post()

        result = self.parse_response(r)

        if not self.verify_device_lock() and result is True:
            result = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02017:

    '''
    POST /api/device/lock
    Verify Add message (optional)
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '020170201702017'
        self.message = 'test_message'
        self.tester_mail = 'test02017@hopebaytech.com'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_data({'imei': self.imei, 'message': self.message})

    def verify_device_lock(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def setup(self):
        # creat device
        self.create_device()

        # restore lock header
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})

    def teardown(self):

        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        return True, '' if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

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


class TeraClientServer_02018:

    '''
    POST /api/device/lock
    Verify message is none
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '020180201802018'
        self.tester_mail = 'test02018@hopebaytech.com'
        self.message = None

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker.set_data({'imei': self.imei, 'message': self.message})

    def verify_device_lock(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def setup(self):

        # creat device
        self.create_device()

        # restore lock header
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})

    def teardown(self):

        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        return True, '' if r.result is True else (
            False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_lock() and result[0] is True:

            result = (
                False,
                'Device lock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02019:

    '''
    POST /api/device/lock
    Verify message is garbled
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '020190201902019'
        self.message = '皜祈岫&#26368;@M?瀢CA6?v肴?X疻?m樖'
        self.tester_mail = 'test02019@hopebaytech.com'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        self.apiworker = APIRequestWorker('/api/device/lock')
        self.apiworker.set_data({'imei': self.imei, 'message': self.message})

    def verify_device_lock(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:
                if str(i['service_state']) != 'disabled':
                    return True
        return False

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'}

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def setup(self):
        # creat device
        self.create_device()

        # restore lock header
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})

    def teardown(self):

        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        return True, '' if r.result else (False, (r.status_code, r.text))

    def run(self):

        self.setup()

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


class TeraClientServer_02020:

    '''
    POST /api/device/unlock
    Verify expire token
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '020200202002020'
        self.tester_mail = 'test02020@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # locked devices
        self.apiworker = APIRequestWorker('/api/device/unlock')
        self.apiworker.set_data({'imei': self.imei})

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def verify_device_unlock(self):

        self.auth_token = self.apiworker.get_auth_token()
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:

                if str(i['service_state']) != 'activated':
                    return True
        return False

    def setup(self):

        # creat device
        self.create_device()

        # restore apiworker header
        self.apiworker.set_header({'X-Access-Token': self.expire_token})

        # lock deivice
        self.lock_worker = APIRequestWorker('/api/device/lock')
        self.lock_worker.set_header({'X-Access-Token': self.tester_mail})
        self.lock_worker.set_data({'imei': self.imei})

        self.lock_worker.post()

    def teardown(self):
        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        if r.json and r.result is False:
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

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_unlock() and result[0] is True:
            result = (
                False,
                'Device unlock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02021:

    '''
    POST /api/device/erase
    Verify expire token
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '020210202102021'
        self.tester_mail = 'test02021@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # locked devices
        self.apiworker = APIRequestWorker('/api/device/erase')
        self.apiworker.set_data({'imei': self.imei})

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def verify_device_unlock(self):

        self.auth_token = self.apiworker.get_auth_token()
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:

                if str(i['service_state']) != 'activated':
                    return True
        return False

    def setup(self):

        # creat device
        self.create_device()

        # restore apiworker header
        self.apiworker.set_header({'X-Access-Token': self.expire_token})

        # lock deivice
        self.lock_worker = APIRequestWorker('/api/device/lock')
        self.lock_worker.set_header({'X-Access-Token': self.tester_mail})
        self.lock_worker.set_data({'imei': self.imei})

        self.lock_worker.post()

    def teardown(self):
        # unlock
        self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        self.apiworker_2.set_data({'imei': self.imei})

        self.apiworker_2.post()

    def parse_response(self, r):

        if r.json and r.result is False:
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

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_unlock():
            result = (
                False,
                'Device unlock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02022:

    '''
    POST /api/device/erase
    Verify device not locked
    '''

    def __init__(self):

        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = '020220202202022'
        self.tester_mail = 'test02022@hopebaytech.com'
        self.error_msg = 'erase_device_service failed !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # locked devices
        self.apiworker = APIRequestWorker('/api/device/erase')
        self.apiworker.set_data({'imei': self.imei})

    def create_device(self):

        self.auth_token = self.apiworker.get_social_oauth_token(
            self.tester_mail)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker.set_header(self.api_headers)
        self.apiworker.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def verify_device_unlock(self):

        self.auth_token = self.apiworker.get_auth_token()
        self.apiworker.set_header({'Authorization': 'JWT ' + self.auth_token})

        r = self.apiworker.query_user_devices()

        if r.status_code > 399:
            return True

        for i in r.json():
            if i['device']['imei'] == self.imei:

                if str(i['service_state']) != 'activated':
                    return True
        return False

    def setup(self):

        # creat device
        self.create_device()

        # restore apiworker header
        self.apiworker.set_header({'X-Access-Token': self.tester_mail})

        # lock deivice
        # self.lock_worker = APIRequestWorker('/api/device/lock')
        # self.lock_worker.set_header({'X-Access-Token': self.tester_mail})
        # self.lock_worker.set_data({'imei': self.imei})

        # self.lock_worker.post()

    def teardown(self):
        # unlock
        # self.apiworker_2 = APIRequestWorker('/api/device/unlock')
        # self.apiworker_2.set_header({'X-Access-Token': self.tester_mail})
        # self.apiworker_2.set_data({'imei': self.imei})

        # self.apiworker_2.post()
        pass

    def parse_response(self, r):

        if r.json and r.result == False:
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

        r = self.apiworker.post()

        result = self.parse_response(r)

        if self.verify_device_unlock():
            result = (
                False,
                'Device unlock fail. status code : {0}, text : {1}'.format(
                    r.status_code,
                    r.text))

        self.teardown()

        return result


class TeraClientServer_02023:

    '''
    GET /api/file/{inode}/download
    Verify expire token
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020230202302023"
        self.social_auth = 'test02023@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.data_inode = '9286'
        self.file_name = 'r1S7X.jpg'
        self.file_md5 = 'c024b4093de697f830b7ee887ec0defe'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        # self.expire_token = None
        self.apiworker.set_header(
            {'X-Access-Token': self.expire_token, 'X-Imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def teardown(self):
        # clean files
        if os.path.isfile(self.file_name):
            os.remove(self.file_name)

    def parse_response(self, r):

        if r.json and r.result is False:
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

        self.create_new_devices()

        # r = self.apiworker.get()
        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02024:

    '''
    GET /api/file/{inode}/download
    Verify img data (.jpg)
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020240202402024"
        self.social_auth = 'test02024@hopebaytech.com'
        self.data_inode = '9286'
        self.file_name = 'r1S7X.jpg'
        self.file_md5 = 'c024b4093de697f830b7ee887ec0defe'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        # self.expire_token = None
        self.apiworker.set_header(
            {'X-Access-Token': self.social_auth, 'X-Imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def teardown(self):
        # clean files

        os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:
            # check md5
            result = self.terafonn_web_server.check_file_md5(self.file_name)

            if result and self.file_md5 == result[1]:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        self.setup()

        self.create_new_devices()

        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02025:

    '''
    GET /api/file/{inode}/download
    Verify video data (.mp4)
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020250202502025"
        self.social_auth = 'test02025@hopebaytech.com'
        self.data_inode = '9285'
        self.file_name = '911_cover.mp4'
        self.file_md5 = 'c6de223dc151de11d53dd86d94d34fae'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        # self.expire_token = None
        self.apiworker.set_header(
            {'X-Access-Token': self.social_auth, 'X-Imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def teardown(self):
        # clean files
        os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:
            # check md5
            result = self.terafonn_web_server.check_file_md5(self.file_name)

            if result and self.file_md5 == result[1]:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        self.setup()

        self.create_new_devices()

        # r = self.apiworker.get()
        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        self.teardown()

        return result


class TeraClientServer_02026:

    '''
    GET /api/file/{inode}/download
    Verify many object data (size > 2M)
    '''

    def __init__(self):

        # setup - init
        self.terafonn_web_server = InitTerafonnWebServer()
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020260202602026"
        self.social_auth = 'test02026@hopebaytech.com'
        self.data_inode = '9283'
        self.file_name = 'test_data_2m'
        self.file_md5 = 'b2d1236c286a3c0704224fe4105eca49'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.data_inode + '/download')

        # self.expire_token = None
        self.apiworker.set_header(
            {'X-Access-Token': self.social_auth, 'X-Imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def teardown(self):
        # clean files

        os.remove(self.file_name)

    def parse_response(self, r):

        if r.result:
            # check md5
            result = self.terafonn_web_server.check_file_md5(self.file_name)

            if result and self.file_md5 == result[1]:
                return (True, '')
            else:
                return (False, 'Check md5 error , msg:' + str(result[1]))

        else:
            return (False, (r.status_code, 'Download Error'))

    def run(self):

        self.setup()

        self.create_new_devices()

        # r = self.apiworker.get()
        r = self.apiworker.download(data_name=self.file_name)

        result = self.parse_response(r)

        # self.teardown()

        return result


class TeraClientServer_02027:

    '''
    GET /api/files/{inode}/info
    Verify expire token
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020270202702027"
        self.social_auth = 'test02027@hopebaytech.com'
        self.meta_inode = '9286'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker(
            '/api/file/' + self.meta_inode + '/info')

        # self.expire_token = None
        self.apiworker.set_header(
            {'X-Access-Token': self.expire_token, 'imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        self.create_new_devices()

        r = self.apiworker.get()

        return self.parse_response(r)


class TeraClientServer_02028:

    '''
    POST /api/webdav/enable
    Verify expire token
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020280202802028"
        self.social_auth = 'test02028@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.new_password = 'Aa123456'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/enable')
        self.apiworker.set_header({'X-Access-Token': self.expire_token})
        self.apiworker.set_data({'imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02029:

    '''
    POST /api/webdav/disable
    Verify expire token
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020290202902029"
        self.social_auth = 'test02029@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.new_password = 'Aa123456'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/disable')
        self.apiworker.set_header({'X-Access-Token': self.expire_token})
        self.apiworker.set_data({'imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

        # Enable webdav
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        r = self.apiworker.post()

        return self.parse_response(r)


class TeraClientServer_02030:

    '''
    PUT /api/webdav/
    Verify expire token
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "010140101401014"
        self.social_auth = 'test01014@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.new_password = 'Aa123456'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')

        self.apiworker.set_header({'X-Access-Token': self.expire_token})
        self.apiworker.set_data({'imei': self.imei,
                                 'origin_password': self.new_password,
                                 'new_password': 'abc123456'})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

        # Enable webdav
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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
                return (False, (r.status_code, r.text))
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.put()

        return self.parse_response(r)


class TeraClientServer_02031:

    '''
    PUT /api/webdav/
    Verify new password less 6 characters
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020310203102031"
        self.social_auth = 'test02031@hopebaytech.com'
        self.new_password = 'Aa'
        self.error_msg = 'invalid input !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data({'imei': self.imei,
                                 'new_password': self.new_password})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

        # Enable webdav
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        return self.parse_response(r)


class TeraClientServer_02032:

    '''
    PUT /api/webdav/
    Verify change password (orgin password is wrong)
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020320203202032"
        self.social_auth = 'test02032@hopebaytech.com'
        self.origin_password = 'test02031'
        self.wrong_orgin = 'test02031wrogin'
        self.new_password = 'Aa123456'
        self.error_msg = 'password is incorrect !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')

        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data({'imei': self.imei,
                                 'origin_password': self.wrong_orgin,
                                 'new_password': self.new_password})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.origin_password})
        self.apiworker_setup.put()

        # Enable webda
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        return self.parse_response(r)


class TeraClientServer_02033:

    '''
    PUT /api/webdav/
    Verify change password (orgin password is right)
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020330203302033"
        self.social_auth = 'test02033@hopebaytech.com'
        self.origin_password = 'test02033'
        self.new_password = 'Aa123456'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')

        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data({'imei': self.imei,
                                 'origin_password': self.origin_password,
                                 'new_password': self.new_password})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.origin_password})
        self.apiworker_setup.put()

        # Enable webdav
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def teardown(self):

        # change password
        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei,
                                       'origin_password': self.new_password,
                                       'new_password': self.origin_password})
        self.apiworker_setup.put()

    def parse_response(self, r):

        return (
            True, '') if r.result is True else (
            False, (r.status_code, r.text))

    def run(self):

        self.setup()

        r = self.apiworker.put()

        self.teardown()

        return self.parse_response(r)


class TeraClientServer_02034:

    '''
    GET /api/webdav/
    Verify expire token
    '''

    def __init__(self):

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "020340203402034"
        self.social_auth = 'test02034@hopebaytech.com'
        self.expire_token = 'expire_token@hopebaytech.com'
        self.new_password = 'Aa123456'
        self.error_msg = 'token expired !'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

        # /api/files setup
        self.apiworker = APIRequestWorker('/api/webdav/')
        self.apiworker.set_header(
            {'X-Access-Token': self.expire_token, 'imei': self.imei})

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password

        self.apiworker_setup = APIRequestWorker('/api/webdav/')
        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker_setup.put()

        # Enable webdav
        self.apiworker_setup = APIRequestWorker('/api/webdav/enable')

        self.apiworker_setup.set_header({'X-Access-Token': self.social_auth})
        self.apiworker_setup.set_data({'imei': self.imei})
        self.apiworker_setup.post()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is False:
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

        r = self.apiworker.get()

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

        # setup - init
        self.apiworker_admin = APIRequestWorker()
        self.apiworker_user = APIRequestWorker()
        self.username = 'hopebayadmin'
        self.password = '4nXiC9X6'
        self.imei = "030010300103001"
        self.social_auth = 'test03001@hopebaytech.com'
        self.new_password = 'Aa123456'

        # get available activation code by admin
        self.auth_token = self.apiworker_admin.get_auth_token_by_user(
            self.username, self.password)
        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }
        self.apiworker_admin.set_header(self.api_headers)
        self.code = self.apiworker_admin.get_available_activation_code()

    def setup(self):

        self.terafonn_web_server = InitTerafonnWebServer()

        self.terafonn_web_server.reset_mongodb()

        self.create_new_devices()

        # Set password
        self.apiworker = APIRequestWorker('/api/webdav/')

        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data(
            {'imei': self.imei, 'new_password': self.new_password})
        self.apiworker.put()

        # Enable webdav
        self.apiworker = APIRequestWorker('/api/webdav/enable')

        self.apiworker.set_header({'X-Access-Token': self.social_auth})
        self.apiworker.set_data({'imei': self.imei})
        self.apiworker.post()

        # Get url
        self.apiworker = APIRequestWorker('/api/webdav/')

        self.apiworker.set_header(
            {'X-Access-Token': self.social_auth, 'X-Imei': self.imei})

        self.webdav_URL = self.apiworker.get().json['url']
        # pdb.set_trace()

    def create_new_devices(self):

        self.auth_token = self.apiworker_user.get_social_oauth_token(
            self.social_auth)

        self.api_headers = {
            'Authorization': 'JWT ' + self.auth_token,
            'Content-Type': 'application/json'
        }

        self.apiworker_user.set_header(self.api_headers)
        self.apiworker_user.register_user({
            "imei_code": self.imei,
            "activation_code": self.code,
            "force": False,
            "vendor": "HopeBay",
            "model": "test_model",
            "android_version": "1.0.0",
            "HCFS_version": "2.1.1.1234",
            "mgmt_app_version": "1.0.0.1234",
            "launcher_version": "1.0.0.5678"
        })

    def parse_response(self, r):

        if r.json and r.result is True:

            if r.json['result'] is True:
                return (True, '')
            else:
                return (False, 'result key error , key:' +
                        str(sorted(r.json.keys())))
        else:
            return (False, (r.status_code, r.text))

    def run(self):

        self.setup()

        return (True, '')


class TeraClientServer_03002:

    '''
    GET /api/system_logs
    '''

    def __init__(self):
        pass

    def run(self):
        return False, 'Testcase is not implemented'


class TeraClientServer_03003:

    '''
    GET /api/system_logs
    '''

    def __init__(self):
        pass

    def run(self):
        return False, 'Testcase is not implemented'


class TeraClientServer_99999:

    '''
    clearn environment
    '''

    def __init__(self):
        self.terafonn_web_server = InitTerafonnWebServer()

    def run(self):

        # kill server
        # self.terafonn_web_server.kill_Terafonn_Web_Server()
        self.terafonn_web_server.kill_fake_arkflex_server()
        self.terafonn_web_server.kill_fake_swfit_server()

        return (True, '')

if __name__ == '__main__':
    pass
    # terafonn_web_server = InitTerafonnWebServer()
    # terafonn_web_server.launch_Terafonn_Web_Server()
    # time.sleep(20)
    # terafonn_web_server.kill_Terafonn_Web_Server()
