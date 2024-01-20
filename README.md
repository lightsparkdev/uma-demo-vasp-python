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

## Running with Docker

You can also run this server with Docker. First we need to build the image. From the root directory of this repo, run:

```bash
docker build -t uma-vasp-python .
```

Next, we need to set up the config variables. You can do this by creating a file called `local.env` in the root
directory of this repo. This file should contain the following:

```bash
LIGHTSPARK_API_TOKEN_CLIENT_ID=<your lightspark API token client ID from https://app.lightspark.com/api-config>
LIGHTSPARK_API_TOKEN_CLIENT_SECRET=<your lightspark API token client secret from https://app.lightspark.com/api-config>
LIGHTSPARK_UMA_NODE_ID=<your lightspark node ID. ex: LightsparkNodeWithOSKLND:018b24d0-1c45-f96b-0000-1ed0328b72cc>
LIGHTSPARK_UMA_RECEIVER_USER=<receiver UMA>
LIGHTSPARK_UMA_ENCRYPTION_PUBKEY=<hex-encoded encryption pubkey>
LIGHTSPARK_UMA_ENCRYPTION_PRIVKEY=<hex-encoded encryption privkey>
LIGHTSPARK_UMA_SIGNING_PUBKEY=<hex-encoded signing pubkey>
LIGHTSPARK_UMA_SIGNING_PRIVKEY=<hex-encoded signing privkey>

# If you are using an OSK node:
LIGHTSPARK_UMA_OSK_NODE_SIGNING_KEY_PASSWORD=<password for the signing key>

# If you are using a remote signing node:
LIGHTSPARK_UMA_REMOTE_SIGNING_NODE_MASTER_SEED=<hex-encoded master seed>

# Optional: A custom VASP domain in case you're hosting this at a fixed hostname.
LIGHTSPARK_UMA_VASP_DOMAIN=<your custom VASP domain. ex: vasp1.example.com>
```

Then, run the image:

```bash
docker run --env-file local.env -p 5000:5000 uma-vasp-python
```
