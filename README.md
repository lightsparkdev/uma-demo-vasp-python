# UMA Demo Server

An example UMA VASP server implementation using Python.

## Installation

```bash
pipenv install --dev
```

## Running

```bash
pipenv run flask --app uma_vasp run
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
# These can be found at https://app.lightspark.com/api-config
LIGHTSPARK_API_TOKEN_CLIENT_ID=<your lightspark API token client ID from>
LIGHTSPARK_API_TOKEN_CLIENT_SECRET=<your lightspark API token client secret>
LIGHTSPARK_UMA_NODE_ID=<your lightspark node ID. ex: LightsparkNodeWithOSKLND:018b24d0-1c45-f96b-0000-1ed0328b72cc>

# These can be generated as described at https://docs.uma.me/uma-standard/keys-authentication-encryption
LIGHTSPARK_UMA_ENCRYPTION_CERT_CHAIN=<PEM-encoded cert chain ordered from leaf to root>
LIGHTSPARK_UMA_ENCRYPTION_PUBKEY=<hex-encoded encryption pubkey>
LIGHTSPARK_UMA_ENCRYPTION_PRIVKEY=<hex-encoded encryption privkey>
LIGHTSPARK_UMA_SIGNING_CERT_CHAIN=<PEM-encoded cert chain ordered from leaf to root>
LIGHTSPARK_UMA_SIGNING_PUBKEY=<hex-encoded signing pubkey>
LIGHTSPARK_UMA_SIGNING_PRIVKEY=<hex-encoded signing privkey>

# These credentials are used for Basic Auth for both the sender and receiver.
LIGHTSPARK_UMA_RECEIVER_USER=<sender UMA>
LIGHTSPARK_UMA_RECEIVER_USER_PASSWORD=<Auth password on the sender side>

# If you are using an OSK node:
LIGHTSPARK_UMA_OSK_NODE_SIGNING_KEY_PASSWORD=<password for the signing key>

# If you are using a remote signing node:
LIGHTSPARK_UMA_REMOTE_SIGNING_NODE_MASTER_SEED=<hex-encoded master seed>

# Optional: A custom VASP domain in case you're hosting this at a fixed hostname.
LIGHTSPARK_UMA_VASP_DOMAIN=<your custom VASP domain. ex: vasp1.example.com>

# If you want to try UMA Auth, you'll need to set these as well:

# You can get these using the ES256 algorithm from jwt.io. This is just an example keypair.
NWC_JWT_PUBKEY = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\nq9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n-----END PUBLIC KEY-----"
NWC_JWT_PRIVKEY = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\nOF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n-----END PRIVATE KEY-----"
LIGHTSPARK_NWC_SERVER_DOMAIN=localhost:8080
```

Then, run the image:

```bash
docker run --env-file local.env -p 5000:5000 uma-vasp-python
```

This will run the server on port 5000. You can change the port by changing the first `5000` in the command above.

## Sending a request

Once the server is running, you can send a request to it using curl. Assuming your server is running on port 9000 with another
VASP running on port 8081, you can run the following to have Alice (`$alice@localhost:9000`) pay Bob (`$bob@localhost:8081`).

```bash
# First, call to vasp1 to lookup Bob at vasp2. This will return currency conversion info, etc. It will also contain a 
# callback ID that you'll need for the next call
$ curl -X GET http://localhost:9000/api/umalookup/\$bob@localhost:8081 -u alice:pa55word

# Now, call to vasp1 to get a payment request from vasp2. Replace the last path component here with the callbackUuid
# from the previous call. This will return an invoice and another callback ID that you'll need for the next call.
$ curl -X GET "http://localhost:9000/api/umapayreq/52ca86cd-62ed-4110-9774-4e07b9aa1f0e?amount=100&currencyCode=USD" -u alice:pa55word

# Now, call to vasp1 to send the payment. Replace the last path component here with the callbackUuid from the payreq
# call. This will return a payment ID that you can use to check the status of the payment.
curl -X POST http://localhost:9000/api/sendpayment/e26cbee9-f09d-4ada-a731-965cbd043d50 -u alice:pa55word
```
