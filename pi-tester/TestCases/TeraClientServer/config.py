import socket
import fcntl
import struct


HOST_NAME = socket.gethostbyname('terafonnreg.hopebaytech.com')

# MANAGMENT_HOST_URL = 'https://192.168.63.137'
MANAGMENT_HOST_URL = 'https://'+HOST_NAME

TERA_CLIENT_HOST_URL = 'http://'+HOST_NAME+':8000'

FAKE_CONTROLLER_SERVER_URL = 'http://localhost:7070'

Test_Email = 'hopebaytest1@gmail.com'

Test_Password = '4nXiC9X6'

#-----cache db-----
settings = {}
settings["mongodb"] = "mongodb://db:27017"
settings["db_name"] = "meta_data"

# ---------------
DEFAULT_IMEI = '123456789012347'
DEFAULT_MODEL_ID = 1
API_DOMAIN_PORT = 5000

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

FAKE_SERVER_IP = socket.gethostbyname('fake.backend')
# FAKE_SERVER_IP = get_ip_address('eth0')
DEFAULT_BACKEND = {
    "domain": 'http://' +
    FAKE_SERVER_IP,
    "backend_type": "swift",
    "port": 8080,
    "TLS": 'false',
    "server_count": 1,
    "max_user": 10000,
    "api_domain": 'http://' +
    FAKE_SERVER_IP +
    ':' +
    str(API_DOMAIN_PORT)}
DEFAULT_DEVICES = {
    "imei": DEFAULT_IMEI,
    "model": 1,
    "state": "not activated",
}
DEFAULT_MODEL = {
    "vendor": "001",
    "name": "test_model",
    "desc": "test desc",
    "default_quota": 1099511627776,
    "default_bandwidth": 104857600,
    "warranty_month": 24
}
DEFAULT_ACTIVATION_CODE = {
    "count": 50,
    "expire_date": "2016-12-25",
    "model": 1
}
