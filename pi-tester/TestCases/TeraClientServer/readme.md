# Prepare Environment for Test

## C Develop Envrionment
```bash
$ sudo apt-get install build-essential
$ sudo apt-get install openssl libssl-dev
```

## Python Libraries
#### Third party libraries
```bash
$ pip install requests
$ pip install selenium
$ pip install pyOpenSSL
```
## Selenium without browser Libraries
```bash
$ sudo apt-get install xvfb
$ pip install pyvirtualdisplay
```
#### HB libraray
```bash
$ cd web/deploy/hb_crypt
$ python setup.py install
```

## Started Server

* **Case HCFSServer_00000 will start these two fake servers automatically:**
	* fake_arkflex_api_server.py  - port 8000 (TeraFonn Client)
	* fake_swift_server.py - port 443 (SSL)

## Setting Host
*  **Change Host-name**
    * default is 'p5p1' (this is CI host name)
    * Need to change files : 
        * fake_arkflex_api_server / fake_arkflex_api_server.py 
        * fake_swift_server / fake_swift_server.py 
        * change_mgmt_url.py 
        * config.py"

## How to Auto Run Settings
* **Running setup.sh**
    * Actions
        * Pull mgmt image from docker:5000
        * Build mgmt
        * Build TeraClient
        * Backup settings file
        * kill 8080 port docker ps
        * change settings networl host name
    * example：
```bash
bash setup.sh
```

# Test Methodology:

## Generic API Test
Mostly, the test will send the request to HCFS Management server and check the response data.
(Use pi-tester)

# Files Info:

#### Config.py
This file will setup the global setting for testing

#### TeraClientServer.py
The mainly testing logical and script are place in here.

####  fake_arkflex_api_server.py
The files is arkflex U fake server , running localhost and 5000 port

####  fake_swift_server.py
The files is Swift fake server , running localhost and 8080 port

####  test_data/
This folder is Storing meta data for fake swift server 

### Requirement

```bash
pip install locustio
pip install pyzmq
```
Pi-Tester will try to create mass request (account creation) to HCFS server.
