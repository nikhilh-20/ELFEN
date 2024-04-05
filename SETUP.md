# ELFEN Setup - Local Installation

This document details the steps required to set up ELFEN locally outside a Docker environment. While it is preferable to
always run ELFEN inside a Docker container, some users have requested a guide to set it up locally. ELFEN has only been
tested on an Ubuntu 22.04 host.

**NOTE: This document details the basic steps required to set up ELFEN locally and quickly get it running. It doesn't
consider whether the steps are secure or not. Users are advised to take necessary precautions to secure their system.**

## Install Dependencies

```bash
$ sudo apt update
$ sudo apt install -y libkrb5-dev postgresql postgresql-contrib libpq-dev mysql-server libmysqlclient-dev python3.10-dev \
    curl gnupg apt-transport-https erlang-base erlang-asn1 erlang-crypto erlang-eldap erlang-ftp erlang-inets \
    erlang-mnesia erlang-os-mon erlang-parsetools erlang-public-key erlang-runtime-tools erlang-snmp erlang-ssl \
    erlang-syntax-tools erlang-tftp erlang-tools erlang-xmerl rabbitmq-server graphviz graphviz-dev qemu-system automake \
    libtool make gcc pkg-config libmagic-dev git python3.10-venv g++
```

## Setup PostgreSQL and MySQL

ELFEN requires an `elfen` user and `elfen_db` database in PostgreSQL and MySQL. The `elfen` user must also have full
privileges on the `elfen_db` database.

### PostgreSQL

```bash
$ sudo -i -u postgres
$ psql
```
```sql
# CREATE USER elfen WITH PASSWORD 'elfen';
# CREATE DATABASE "elfen_db";
# ALTER USER elfen CREATEDB;
# ALTER ROLE elfen SET client_encoding to 'utf8';
# ALTER ROLE elfen SET default_transaction_isolation TO 'read committed';
# GRANT ALL PRIVILEGES ON DATABASE elfen_db TO elfen;
```

### MySQL

```bash
$ sudo mysql
```
```sql
> ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password';
> Ctrl-D
```
```bash
$ sudo mysql_secure_installation
...
...
Enter password for user root: <enter "password">

VALIDATE PASSWORD COMPONENT can be used to test passwords
...
Press y|Y for Yes, any other key for No: n
...
...
Change the password for root ? ((Press y|Y for Yes, any other key for No) : n
...
...
Remove anonymous users? (Press y|Y for Yes, any other key for No) : y
...
...
Disallow root login remotely? (Press y|Y for Yes, any other key for No) : y
...
...
Remove test database and access to it? (Press y|Y for Yes, any other key for No) : y
...
...
Reload privilege tables now? (Press y|Y for Yes, any other key for No) : y

$ mysql -u root -p
<enter "password">
```
```sql
> ALTER USER 'root'@'localhost' IDENTIFIED WITH auth_socket;
> Ctrl-D
```
```bash
$ sudo mysql
```
```sql
> CREATE USER 'elfen'@'localhost' IDENTIFIED BY 'elfen';
> GRANT CREATE, ALTER, DROP, INSERT, UPDATE, INDEX, DELETE, SELECT, REFERENCES, RELOAD on *.* TO 'elfen'@'localhost';
> FLUSH PRIVILEGES;
> CREATE DATABASE elfen_db;
> Ctrl-D
```

## Setup RabbitMQ

```bash
$ sudo rabbitmq-plugins enable rabbitmq_management
$ sudo rabbitmqctl add_user elfen elfen
$ sudo rabbitmqctl set_user_tags elfen administrator
$ sudo rabbitmqctl delete_user guest
```

Go to RabbitMQ management console (http://localhost:15672), login with `elfen:elfen` and provide `'elfen` user access to
vhost '`/`'
* After logging in, go to `Admin` tab.
* Click on `elfen` user.
* Under the `Set permission` section, select `/` as the `Virtual Host` and click on the `Set permission` button.
* Click on `Admin` tab again and verify that `Can access virtual hosts` is set to `/` for the `elfen` user.

## Setup YARA v4.2.3

```bash
$ cd /tmp
$ wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.2.3.tar.gz
$ tar xzf v4.2.3.tar.gz
$ cd yara-4.2.3
$ ./bootstrap.sh
$ ./configure --enable-magic
$ make && sudo make install
$ sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
$ sudo ldconfig
```

## Setup Go and `elfinfo`

```bash
$ cd /tmp/
$ wget https://go.dev/dl/go1.19.5.linux-amd64.tar.gz
$ gzip -d go1.19.5.linux-amd64.tar.gz
$ tar -xf go1.19.5.linux-amd64.tar
$ sudo mv go /usr/local
$ export PATH=$PATH:/usr/local/go/bin
$ go install github.com/xyproto/elfinfo@latest
```
Add `~/go/bin` to `$PATH`. This can be done using `~/.bashrc`:
```bash
$ cat ~/.bashrc
...
...
export PATH=$PATH:~/go/bin

$ source ~/.bashrc
```

## Setup ELFEN

Clone the ELFEN repository. Ensure that you have SSH keys set up for your GitHub account.

```bash
$ git clone --recursive git@github.com:nikhilh-20/ELFEN.git
```

Modify the `ELFEN/elfen/settings.py` file. It should look like this:
```python
DATABASES = {
    "default": {
        ...
        # "HOST": "mysql",
        "HOST": "localhost",
        "PORT": 3306,
        ...
    },
    "elfen": {
        ...
        # "HOST": "postgres",
        "HOST": "localhost",
        "PORT": 5432,
        ...
    }
}
...
...
# CELERY_BROKER_URL = "amqp://elfen:elfen@rabbitmq:5672"
CELERY_BROKER_URL = "amqp://elfen:elfen@localhost:5672"
# CELERY_RESULT_BACKEND = "db+postgresql://elfen:elfen@postgres/elfen_db"
CELERY_RESULT_BACKEND = "db+postgresql://elfen:elfen@localhost/elfen_db"
```

Create necessary subdirectories in ELFEN's root directory, a Python virtual environment, install Python library
requirements, make database migrations and create an ELFEN superuser (`admin:admin`):

```bash
$ mkdir data && cd data && mkdir mysql postgres rabbitmq && cd ..
$ mkdir -p media/web
$ python3.10 -m venv venv
$ source ./venv/bin/activate
(venv) $ pip install -r requirements.txt
(venv) $ python manage.py migrate && python manage.py migrate --database=elfen
(venv) $ python manage.py createsuperuser
<admin:admin>
```

## Start ELFEN

```bash
$ python manage.py runserver 0.0.0.0:8000
$ celery -A ELFEN worker -l INFO -Q submission -n submission_analysis_worker --heartbeat-interval=30 --without-gossip --without-mingle
$ celery -A ELFEN worker -l INFO -Q static_analysis -n static_analysis_worker --heartbeat-interval=30 --without-gossip --without-mingle
$ celery -A ELFEN worker -c 4 -l INFO -Q dynamic_analysis -n dynamic_analysis_worker --heartbeat-interval=120 --without-gossip --without-mingle
$ celery -A ELFEN worker -l INFO -Q network_analysis -n network_analysis_worker --heartbeat-interval=120 --without-gossip --without-mingle
$ celery -A ELFEN worker -l INFO -Q detection_analysis -n detection_analysis_worker --heartbeat-interval=120 --without-gossip --without-mingle
$ celery -A ELFEN worker --beat -l INFO -Q periodic_analysis -n periodic_analysis_worker --heartbeat-interval=120 --without-gossip --without-mingle
```

ELFEN should now be available at http://127.0.0.1:8000. Ensure that your system has sufficient RAM and CPU cores to avoid
adverse performance issues. The above commands can be run as a PyCharm configuration and one can perform debugging within
PyCharm itself.