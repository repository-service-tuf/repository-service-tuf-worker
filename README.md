# kaprien-repo-worker
Kaprien Repository Worker


## Development

### Basic development tooks

- Python >=3.10
- pip
- Pipenv
- Docker

### Preparing development environment

After installing Python, install the pipenv tool.
```shell
$ pip install pipenv
```

Creating a virtual environment for this project.
```shell
$ pipenv shell
```

Install requirements from Pipfile.lock
The flag -d will install the development requirements
```Shell
$ pipenv install -d
```

#### MacOS running on Macbooks M1
For developers, after above command, run
```shell
$ pip uninstall cryptography cffi -y
$ pip cache purge
$ LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi cryptography

```

### Github Account Token

For the development environment, you will require a Github Account Token to
download Kaprien REST API container

Access the Github page > Settings > Develop Settings > Personal Access tokens >
Generate new token

This token requires only
`read:packages Download packages from GitHub Package Registry`

Save the token hash

### Starting

```shell
$ make run-dev
```

Wait until the message above
```shell
kaprien-rest-api_1  | INFO:     Will watch for changes in these directories: ['/opt/kaprien-rest-api']
kaprien-rest-api_1  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
kaprien-rest-api_1  | INFO:     Started reloader process [1] using StatReload
kaprien-rest-api_1  | INFO:     Started server process [8]
kaprien-rest-api_1  | INFO:     Waiting for application startup.
kaprien-rest-api_1  | INFO:     Application startup complete.
```

Run
```shell
$ make init-repository
```

When you see the `201 Created` is ready to use
```shell
kaprien-rest-api_1  | INFO:     192.168.80.4:52666 - "POST /api/v1/bootstrap/ HTTP/1.1" 201 Created
```
Note: You don't need run `make init-repository` every time, only when you
have empty Repository Metadata.

