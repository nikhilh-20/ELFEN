# Troubleshooting

This document goes over some initial troubleshooting steps that you can take when encountering failures in ELFEN. This will evolve over time as more users report issues.

### Issue 1

```
Duplicate entry 'admin' for key 'auth_user.username'
```

When you `docker compose up` the second time onwards, you will see the following docker logs:

```bash
...
elfen-web-1                               | IntegrityError:
elfen-web-1                               | (1062, "Duplicate entry 'admin' for key 'auth_user.username'")
...
```

This is okay. I use a dirty script which creates an `admin` superuser on startup but does not check if that superuser already exists. All you need to check is if the following docker logs come up:

```bash
elfen-web-1                               | System check identified no issues (0 silenced).
elfen-web-1                               | August 31, 2023 - 10:48:00
elfen-web-1                               | Django version 4.1.7, using settings 'ELFEN.settings'
elfen-web-1                               | Starting development server at http://0.0.0.0:8000/
elfen-web-1                               | Quit the server with CONTROL-C.
```

### Issue 2

```
chmod: changing permissions of '/var/lib/postgresql/data': Operation not permitted
```

This was the root cause for the issue reported in [#1](https://github.com/nikhilh-20/ELFEN/issues/1). The `data/postgres` directory was owned by `root` . Since the PostgreSQL container runs as a non-root user (`user: 1000:1000`), it was causing a permission issue in the given setup.

### Issue 3

```
Container is unhealthy
```

I've encountered this issue intermittently. Sometimes it's the `mysql` container which doesn't come up and other times it's some other container. I just re-create ELFEN's containers, or if that doesn't work I rebuild ELFEN from scratch.

```bash
$ docker compose up --force-recreate
```

OR

```bash
$ docker compose build --no-cache
$ docker compose up
```

Note that ELFEN tasks are stored under `data` sub-directories. As long as those files are not touched, you can erase ELFEN docker images completely and you will not lose past data.