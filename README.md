# Cryptex

A command API for accessing various keychains or secure enclaves.

## The problem

Applications use several credentials today to secure data locally and during transmission.
However, bad habits happen when safeguarding these credentials. For example, when creating an API token for Amazon's AWS, Amazon generates
a secret key on a user's behalf and is downloaded to a CSV file. Programmers do not know how to best
store these downloaded credentials because they must be used in a program to make API calls.
They don't know which of the following is the best option:

- Put these credentials directly in the program like most do as constant variables but this is a terrible option because attackers can analyze the code and extract it.
- Use environment variables. If so, should it be passed at the command level or put in a global variable registry? Both are susceptible to sniffing memory or process information.
- Read a config file that contains the credentials but must rely on the security of the operating system to manage access control.
- Use secure enclaves to store the credentials but this just shifts to another problem as secure enclaves rely on yet another set of credentials to ensure the application has the correct authorization. These come as hardware security modules (HSM) or trusted execution environments (TEE).
- Require interaction with a user or group to supply the credential for each use or cache it for a period of time. This is usually done with passwords, pins, cyber tokens, and biometrics.

Where to put the credential that is directly used by applications or people is called the top level credential problem.

There are services like [LeakLooker](https://github.com/woj-ciech/LeakLooker) that browse the internet looking for credentials that can be scraped and unfortunately but often [succeed](https://hackernoon.com/leaklooker-v2-find-more-open-servers-and-source-code-leaks-25e671700e41?mc_cid=47325dd839&mc_eid=0ff0c85eaf).
Some projects have documented how to test credentials to see if they have been revealed. See [keyhacks](https://github.com/streaak/keyhacks).

This document aims to provide guidance and aid in adopting best practices and developing code to address the top level credential problem — the credential used to protect all others — the keys to the kingdom — or a secret that is used directly by a program that if compromised would yield disastrous consequences.

## The solution

*Cryptex* is a layer that is designed to be a command line tool or API library for storing secrets that tries to make it hard to get wrong.
The default is to use the operating system keychain. The goal is to add to *Cryptex* to allow for
many different enclaves that are optimal for storing the keys to the kingdom like YubiKey, Intel SGX, or Arm Trustzone.
In principle, a system's secure enclave should be able to keep some credentials away from `root` (as in, the attacker can *use* the credential as long as they have access, but they can't extract the credential for persistence), and assuming no other attacks like [Foreshadow](https://foreshadowattack.eu/).

Mac OS X, Linux, and Android have built-in keychains that are guarded by the operating system.
iOS and Android come with hardware secure enclaves or trusted execution environments for managing the secrets stored in the keychain.

This first iteration uses the OS keychain or an equivalent and uses the command line or is a C callable API.
Future work could allow for communication over unix or tcp sockets with *Cryptex* running as a daemon process.

Currently Mac OS X offers support for a [CLI tool](https://www.netmeister.org/blog/keychain-passwords.html) and [libraries](https://developer.apple.com/documentation/security) but they are complex to understand and can be prone to misuse due to misunderstandings.
*Cryptex* removes the complexity by choosing secure defaults so developers can focus on their job.

*Cryptex* is written in Rust and has no external dependencies to do its job except DBus on Linux.

*Cryptex* also allows for using [SQLCipher](https://www.zetetic.net/sqlcipher/) instead of keyring via the `feature=file`.
You can check if SQLCipher is enabled by running the function `allows_file()`.
This approach uses two inputs to create the encryption key: a user selected password, and random system generated data.
Similar to how databases use connection strings, this library employs a connection string to indicate the values as well.
The connection string syntax is `password=<password> salt=<hex encoded salt value>`. This value is hashed using Argon2id
and thus the memory, threads, and degree of parallelism can also be set as part of the string
`memory=<integer> threads=<integer> parallel=<integer>`.

The program can be compiled from any OS to run on any OS. Cryptex-CLI is the command line tool while Cryptex is the library.

---

## KMS/HSM Backends

Beyond OS keychains and SQLCipher, Cryptex supports a class of backends where a **Key Management
Service (KMS) or Hardware Security Module (HSM)** holds one master HMAC-SHA256 key that never
leaves the device, and Cryptex stores an unlimited number of secrets as small encrypted files on
disk. This avoids pushing secrets into the KMS itself while still ensuring that every secret is
cryptographically bound to a specific key and device.

### Cryptographic protocol

For each secret stored by a KMS backend:

1. **Nonce** (12 bytes): `SHA-256("cryptex-nonce" ‖ OS_rng₃₂ [‖ backend_rng₃₂])[..12]`
   Two independent entropy sources are mixed so that compromising either one alone does not
   allow nonce prediction.

2. **K_enc** (32 bytes): `HMAC-SHA256(master_key, "cryptex-keyring" ‖ version ‖ key_id ‖ device_id ‖ nonce)`
   This is computed **inside** the KMS/HSM — the raw key never leaves. The HMAC output is
   used directly as a 32-byte AES-256-GCM encryption key, making it per-entry and per-nonce
   unique.

3. **Ciphertext**: `AES-256-GCM(K_enc, nonce, plaintext, AAD)`
   where `AAD = version ‖ key_id ‖ device_id ‖ nonce`.

The `key_id` is the backend's identifier for the signing key (e.g. `"2"` for YubiHSM, a UUID
for AWS KMS). The `device_id` is a 16-byte hash derived from the device/instance identity
(e.g. YubiHSM serial number). Both are stored inside the entry file and bound into the AAD and
HMAC input, so a ciphertext created on one device with one key cannot be decrypted with a
different device or a different key — the GCM authentication tag will fail.

Each secret is stored as a binary file under `~/.cryptex/<backend>/<service>/`, named
`hex(SHA-256(secret_id)).bin`. The file format is:

```
[u16 LE: id_len][id bytes][entry bytes]
```

where `entry bytes` is:

```
version(1) | key_id_len_LE(2) | key_id(variable) | device_id(16) | nonce(12) | ct_len_LE(4) | ciphertext
```

### The `KmsBackend` trait

All KMS/HSM backends implement the `KmsBackend` trait:

```rust
pub trait KmsBackend: Send + Sync {
    /// Short filesystem-safe name, used as a storage directory component.
    fn backend_name(&self) -> &'static str;

    /// The key identifier string (e.g. "2", a UUID, or a KMS ARN).
    fn key_id(&self) -> &str;

    /// A stable 16-byte identifier for the device/instance (e.g. from HSM serial).
    fn device_id(&self) -> [u8; 16];

    /// Optional backend entropy — return Ok(Vec::new()) if unavailable.
    fn get_random(&self, n: usize) -> Result<Vec<u8>>;

    /// Compute HMAC-SHA256 using the backend's secret key.
    fn hmac_sha256(&self, msg: Vec<u8>) -> Result<[u8; 32]>;
}
```

A `KmsKeyRing<B: KmsBackend>` is automatically a `KeyRing` once a backend is provided — all
encryption, decryption, nonce generation, and file I/O are handled by the shared layer.

---

### YubiHSM 2

The `yubihsm-usb` and `yubihsm-http` features enable the [YubiHSM 2](https://www.yubico.com/products/hardware-security-module/) backend.
One HMAC-SHA256 key is stored on the device; Cryptex derives a per-secret AES-256-GCM key
from it without ever exposing the master key.

**Cargo features:**

```toml
[dependencies]
cryptex = { version = "...", features = ["yubihsm-usb"] }
# or
cryptex = { version = "...", features = ["yubihsm-http"] }
```

`yubihsm-usb` communicates directly over libusb (no daemon needed).
`yubihsm-http` communicates via the `yubihsm-connector` HTTP daemon.

#### One-time setup

Before first use, generate the HMAC key on the device (run once per device):

```rust
use cryptex::keyring::yubihsm::YubiHsmKeyRing;

YubiHsmKeyRing::setup(
    "connector=usb auth_key_id=1 password=password domain=1",
    2,  // object ID for the new HMAC key
)?;
```

#### Connection string

```text
# USB (no daemon required, just libusb):
connector=usb hmac_key_id=2 auth_key_id=1 password=password domain=1 service=myapp

# HTTP (requires yubihsm-connector running locally):
connector=http addr=127.0.0.1 port=12345 hmac_key_id=2 auth_key_id=1 password=password domain=1 service=myapp
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `connector` | `usb` | Transport: `usb` or `http` |
| `hmac_key_id` | `1` | Object ID of the HMAC-SHA256 key on the YubiHSM |
| `auth_key_id` | `1` | Object ID of the authentication key |
| `password` | `password` | Authentication key password |
| `domain` | `1` | HSM domain (1–16) |
| `service` | `default` | Service name, used as a storage subdirectory |
| `addr` | `127.0.0.1` | HTTP connector address (http only) |
| `port` | `12345` | HTTP connector port (http only) |

#### Usage

```rust
use cryptex::keyring::{KeyRing, NewKeyRing};
use cryptex::keyring::yubihsm::YubiHsmKeyRing;

let mut ring = YubiHsmKeyRing::new(
    "connector=usb hmac_key_id=2 auth_key_id=1 password=password domain=1 service=myapp"
)?;

ring.set_secret("db-password", b"s3cr3t")?;
let value = ring.get_secret("db-password")?;
ring.delete_secret("db-password")?;

// List stored secrets (id, key_id, device_id) without decrypting:
let entries = ring.list_hsm_secrets()?;
```

---

## Future KMS Backends

The `KmsBackend` trait is designed to be implemented by any system that can compute an
HMAC-SHA256 without exposing the raw key. The following backends are planned:

### AWS KMS

AWS Key Management Service supports [GenerateMAC](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMAC.html)
for HMAC-SHA256 using a symmetric HMAC key. The backend's `key_id` would be the KMS key ARN
or alias (e.g. `arn:aws:kms:us-east-1:123456789012:key/mrk-...`), and `device_id` would
be derived from the AWS account ID and region to provide geographic/account binding.

```text
# Anticipated connection string:
provider=aws-kms key_id=arn:aws:kms:us-east-1:123456789012:key/mrk-... region=us-east-1 service=myapp
```

### Azure Key Vault

Azure Key Vault supports [HMAC operations](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign)
via its managed HSM. The backend's `key_id` would be the Key Vault key identifier URI, and
`device_id` would be derived from the vault's tenant ID and vault name.

```text
# Anticipated connection string:
provider=azure-keyvault vault=https://myvault.vault.azure.net key_id=my-hmac-key service=myapp
```

### HashiCorp Vault

HashiCorp Vault's [Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
supports HMAC computation on stored keys via the `/transit/hmac/:key_name` endpoint. The
backend's `key_id` would be the Transit key name, and `device_id` would be derived from
the Vault cluster identifier.

```text
# Anticipated connection string:
provider=vault addr=https://vault.example.com:8200 token=hvs.xxx key_id=my-hmac-key service=myapp
```

---

## Using as a library

This crate enables running as a Rust library.

```rust
use cryptex::{get_os_keyring, KeyRing};

let mut keyring = get_os_keyring("myapp")?;
keyring.set_secret("test_key", b"secret")?;

// Retrieve secret later
let secret = keyring.get_secret("test_key")?;

// Remove the secret from the keyring
keyring.delete_secret("test_key")?;
```

## Run the program

Basic Usage

Requires dbus library on Linux.

On Ubuntu, this is `libdbus-1-3` when running.
On RedHat, this is `dbus` when running.

Gnome-keyring or KWallet must also be installed on Linux.

*Cryptex* can be run either using **cargo run -- \<args\>** or if it is already built from [source](#build-from-source)
using *./cryptex*.

*Cryptex* tries to determine if input is a file or text. If a file exists that matches the entered text, *Cryptex* will
read the contents. Otherwise, it will prompt the user for either the id of the secret or to enter a secret.

*Cryptex* stores secrets based on a service name and an ID. The service name is the name of the program or process that only is allowed to access the secret with that ID.
Secrets can be retrieved, stored, or deleted.

When secrets are stored, care should be given to not pass the value over the command line as it could be stored in the command line history.
For this reason, either put the value in a file or *Cryptex* will read it from STDIN. After *Cryptex* stores the secret, Cryptex will securely wipe it from memory.

## Caveat

One remaining problem is how to solve the service name provided to *Cryptex*. Ideally *Cryptex* could compute it instead of supplied from the calling endpoint which can lie about the name.
We can imagine an attacker who wants access to the AWS credentials in the keychain just needs to know the service name and the id of the secret to request it. Access is still blocked by
the operating system if the attacker doesn't know the keychain credentials similar to a password vault. If *Cryptex* could compute the service name then this makes it harder for an attacker
to retrieve targeted secrets. However, this is better than the secrets existing in plaintext in code, config files, or environment variables.

## Examples

*Cryptex* takes at least two arguments: service_name and ID.
When storing a secret, an additional parameter is needed. If omitted (the preferred method) the value is read from STDIN.

In the case of using SQLCipher, the service_name is the connection string to be used.

### Storing a secret
```bash
cryptex set aws 1qwasdrtyuhjnjyt987yh
prompt> ...<Return>
Success
```

### Retrieve a secret
```bash
cryptex get aws 1qwasdrtyuhjnjyt987yh
<Secret Value>
```

### Delete a secret
```bash
cryptex delete aws 1qwasdrtyuhjnjyt987yh
```

### List all secrets
*Cryptex* can read all values stored in the keyring. List will just list the name
of all the values in the keyring without retrieving their actual values.
```bash
cryptex list
```

```
{"application": "cryptex", "id": "apikey", "service": "aws", "username": "mike", "xdg:schema": "org.freedesktop.Secret.Generic"}
{"application": "cryptex", "id": "walletkey", "service": "indy", "username": "mike", "xdg:schema": "org.freedesktop.Secret.Generic"}
```

### Peek secrets
*Cryptex* can retrieve all or a subset of secrets in the keyring. Peek without
any arguments will pull out all keyring names and their values. Because Cryptex
encrypts values before storing them in the keyring if it can, those values
will be returned as hex values instead of their associated plaintext.
Peek filtering is different based on the operating system.

For OSX, filtering is based on the **kind** that should be read. It can be __generic__ or __internet__ passwords.
__generic__ only requires the *service* and *account* labels. __internet__ requires the *server*, *account*, *protocol*, *authentication_type* values.
Filters are supplied as name value pairs separated by `=` and multiple pairs separated by a comma.
```bash
cryptex peek service=aws,account=apikey
```

For Linux, filtering is based on a subset of name value pairs of the attributes that match.
For example, if the attributes in the keyring were like this
```
{"application": "cryptex", "id": "apikey", "service": "aws", "username": "mike", "xdg:schema": "org.freedesktop.Secret.Generic"}
{"application": "cryptex", "id": "walletkey", "service": "indy", "username": "mike", "xdg:schema": "org.freedesktop.Secret.Generic"}
```
To filter based on *id*, run
```bash
cryptex peek id=apikey
```
To filter based on *username* AND *service*, run
```bash
cryptex peek username=mike,service=aws
```

For Windows, filtering is based on the credentials targetname and globbing.
For example, if *list* returned
```
{"targetname": "MicrosoftAccount:target=SSO_POP_Device"}
{"targetname": "WindowsLive:target=virtualapp/didlogical"}
{"targetname": "LegacyGeneric:target=IEUser:aws:apikey"}
```
then filtering searches everything after `:target=`. In this case, if the value
to be peeked is IEUser:aws:apikey, the following will return just that result
```bash
cryptex.exe peek IE*
cryptex.exe peek IE*apikey
cryptex.exe peek IEUser:aws:apikey
```

## Build from source
[build-from-source]: #build-from-source

To make a distributable executable, run the following commands:

1. On Linux install the dbus library. On a Debian-based OS this is `libdbus-1-dev`. On a RedHat-based OS this is `dbus-devel`.
1. `curl https://sh.rustup.rs -sSf | sh -s -- -y` — installs the Rust compiler.
1. `cargo build --release` — when this is finished the executable is `target/release/cryptex`.
1. For \*nix users `cp target/release/cryptex /usr/local/bin && chmod +x /usr/local/bin/cryptex`.
1. For Windows users copy `target/release/cryptex.exe` to a folder and add that folder to your `%PATH` variable.

For YubiHSM support, install [libusb](https://libusb.info/) first, then build with:

```bash
cargo build --release --features yubihsm-usb
# or
cargo build --release --features yubihsm-http
```

Libcryptex is the library that can be linked to programs to manage secrets.
Use the library for the underlying operating system that meets your needs:

- **libcryptex.dll** — Windows
- **libcryptex.so** — Linux
- **libcryptex.dylib** — Mac OS X

## Future work

- **AWS KMS backend** — HMAC-SHA256 via `GenerateMAC`, key ID is a KMS key ARN or alias.
- **Azure Key Vault backend** — HMAC via the managed HSM sign endpoint, key ID is a Key Vault key URI.
- **HashiCorp Vault backend** — HMAC via the Transit secrets engine, key ID is a Transit key name.
- Allow for communication over Unix or TCP sockets with *Cryptex* running as a daemon process.
- Allow for steganography methods like using images or Microsoft Office files for storing the secrets.
- Allow for other enclaves like LastPass, 1Password.
