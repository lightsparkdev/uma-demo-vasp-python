# UMA Demo Server

An example UMA VASP server implementation using Python.

## Installation

```bash
pipenv install --dev
```

## Running

```bash
pipenv run flask --app uma_vasp.server run
```

This will run the server on port 5000. You can change the port by setting the `FLASK_RUN_PORT` environment variable.
