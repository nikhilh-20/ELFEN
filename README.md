# ELFEN: Linux Malware Analysis Sandbox

ELFEN is a dockerized sandbox for analyzing Linux (file type: `ELF`) malware. It leverages an array of open-source technologies to perform both static and dynamic analysis. Results are available through both the GUI and API.

Currently, ELFEN supports the analysis of ELF binaries for the following architectures:
* x86-64
* MIPS 32-bit big/little-endian
* PowerPC 32-bit big-endian
* ARMv5 32-bit little-endian

## Getting Started

### Prerequisite

Install docker and docker compose from https://docs.docker.com/engine/install/ubuntu/

### Setup

1. Clone the ELFEN repository

```bash
$ git clone --recursive git@github.com:nikhilh-20/ELFEN.git
```

2. Modify the DJANGO secret key in `ELFEN/settings.py#L30`. The secret key is used by Django for cryptographic purposes and must be secure. It can be generated in the following manner, for example:

```python
import secrets

# ASCII characters range: 33-126
ascii_chars = [chr(i) for i in range(33, 127)]
# Length of SECRET_KEY must be 50 characters minimum
keylen = 60
''.join(secrets.choice(ascii_chars) for i in range(keylen))
```

3. ELFEN uses fixed credentials for the following services. Modify them as needed.
    * MySQL. Refer to `docker/mysql/Dockerfile`.
        * Ensure changes, if any, are also mirrored to `ELFEN/settings.py#L101-L103`
    * PostgreSQL. Refer to `docker/postgres/Dockerfile` and `docker/postgres/init.sql`.
        * Ensure changes, if any, are also mirrored to `ELFEN/settings.py#L115-L117` and `ELFEN/settings.py#L136`
    * RabbitMQ. Refer to `docker/rabbitmq/Dockerfile`.
        * Ensure changes, if any, are also mirrored to `ELFEN/settings.py#L134`

4. ELFEN requires the following ports to be free/available on the host:
    * `5555` (Flower service)
    * `8000` (ELFEN web service)

5. Create required directories in ELFEN root directory.
    * Databases and RabbitMQ data storage
    * ELFEN task data storage (sample binary, dynamic analysis artifacts)
```bash
$ mkdir data && cd data && mkdir mysql postgres rabbitmq && cd ..

$ ls -1q data/
mysql
postgres
rabbitmq

$ mkdir -p media/web
```

6. Modify the `docker-compose.user.yml` to contain your UID and GID. By default, both are set to `1000:1000`.

```bash
# UID
$ id -u
1000

# GID
$ id -g
1000
```

7. Build the ELFEN docker system.

```bash
$ docker compose build
```

8. Bring up ELFEN services.

```bash
$ docker compose -f docker-compose.yml -f docker-compose.user.yml up
...
...
elfen-web-1                               | Performing system checks...
elfen-web-1                               | 
elfen-web-1                               | 
elfen-web-1                               | System check identified no issues (0 silenced).
elfen-web-1                               | August 31, 2023 - 10:46:41
elfen-web-1                               | Django version 4.1.7, using settings 'ELFEN.settings'
elfen-web-1                               | Starting development server at http://0.0.0.0:8000/
elfen-web-1                               | Quit the server with CONTROL-C.
```

A Django superuser, `admin` is also created with password `admin`. ELFEN should now be available on the host at http://127.0.0.1:8000 in **debug** mode.

*Note: ELFEN has only been tested on Ubuntu 22.04.2 LTS host.*

```bash
$ docker --version
Docker version 24.0.4, build 3713ee1

$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.2 LTS
Release:	22.04
Codename:	jammy

$ uname -a
Linux oni 6.2.0-26-generic #26~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Jul 13 16:27:29 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

### Troubleshooting

See the [troubleshooting document](./TROUBLESHOOTING.md) for known issues.

## API

ELFEN provides an API to submit samples and retrieve analysis reports. Ready-to-use scripts are available under the `scripts` directory.

### API Token

#### GUI

To retrieve your API token, visit http://127.0.0.1:8000/api/token/ and login with your username and password. If you're using the default Django superuser, the credentials are `admin:admin`.

You should now see two values: `access` and `refresh` tokens. The `access` token will be valid for 7 days after which it will have to be re-generated (visit http://127.0.0.1:8000/api/token/refresh/) using the `refresh` token (valid for 30 days).

#### IPython

To retrieve your API token, send a `POST` request to http://127.0.0.1:8000/api/token/ with your username and password. If you're using the default Django superuser, the credentials are `admin:admin`.

```python
import requests

username, pwd = "admin", "admin"
r = requests.post("http://127.0.0.1:8000/api/token/", json={"username":username, "password":pwd})

r.json()
{'refresh': '...', 'access': '...'}
```

### Submitting Samples

Copy the `access` token into `scripts/submit_samples.py`. Given a file containing newline-separated full paths to samples, this script can be used to submit them to ELFEN. The output JSON is a mapping between the submitted sample path and ELFEN task UUID.

```bash
$ cat demo_submit 
/full/path/to/1af85af86c92c06dd2d127e0b462679f60d085cfc28cf13c79988b7ef50b95fe

$ python submit_samples.py -f demo_submit -o output.json
Submitted /full/path/to/1af85af86c92c06dd2d127e0b462679f60d085cfc28cf13c79988b7ef50b95fe successfully.

$ cat output.json 
{
    "/full/path/to/1af85af86c92c06dd2d127e0b462679f60d085cfc28cf13c79988b7ef50b95fe": "4122f552-1897-48d0-b906-bb144c6e4010"
}
```

### Retrieving Full Analysis Report

Copy the `access` token into `scripts/get_report_task.py`. Given a task UUID, it retrieves the full analysis JSON report.

```bash
$ python3 get_report_task.py -u 4122f552-1897-48d0-b906-bb144c6e4010 -o report.json
Report retrieved successfully for 4122f552-1897-48d0-b906-bb144c6e4010.

$ du -h report.json 
56K report.json
```

### Retrieving Analysis Report for Given Backend

ELFEN leverages multiple backends to conduct analysis. Some backends like `elfheader` and `capa` are associated with static analysis, whereas others such as `fileops`, `c2config` are associated with dynamic analysis. Reports can be retrieved for a given backend using `scripts/get_report_backend.py`. Copy the `access` token into the script.

```bash
$ python3 get_report_backend.py -u 4122f552-1897-48d0-b906-bb144c6e4010 -b procops -o report.json
Report retrieved successfully for procops for 4122f552-1897-48d0-b906-bb144c6e4010.

$ cat report.json | jq
{
  "submission_uuid": "4122f552-1897-48d0-b906-bb144c6e4010",
  "backend": "procops",
  "report": {
    "errors": false,
    "error_msg": [],
    "data": [
      {
        "ts": "05:10:03.360807 UTC",
        "pid": 130,
        "procname": "Ba9iedKN",
        "func": "getpid",
        "args": "",
        "ret": 130
      },
      {
        "ts": "05:10:03.361229 UTC",
        "pid": 130,
        "procname": "Ba9iedKN",
        "func": "getpid",
        "args": "",
        "ret": 130
      },
      {
        "ts": "05:10:03.363962 UTC",
        "pid": 130,
        "procname": "Ba9iedKN",
        "func": "fork",
        "args": "",
        "ret": 132
      },
      {
        "ts": "05:10:03.388397 UTC",
        "pid": 132,
        "procname": "Ba9iedKN",
        "func": "fork",
        "args": "",
        "ret": 133
      }
    ]
  }
}
```

## Conferences

1. Nullcon Goa 2023
    1. Slides: https://github.com/nikhilh-20/ELFEN/blob/main/docs/Nullcon_Goa_2023_Slides.pdf
    2. Talk: https://www.youtube.com/watch?v=opfwbNlijSg
