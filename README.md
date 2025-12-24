# (bi)bin

A (heavily modified) fork of the excellent [bin](https://github.com/w4/bin) that I used as a starting point for this project.

`(bi)bin` is a pastebin-like project for my own website: quick scratchpad, url shortener, QR code generator... I also added a rudimentary password protection scheme because I did not want to have to curate the content.

It is optimized for speed and can handle hundreds of clients per second (async code with [Rocket](https://rocket.rs/)/[SQLx](https://github.com/launchbadge/sqlx)).

The docker image is built using the official [Docker Hardened images](https://dhi.io/). User ID/Group ID: 65532/65532.

### Persistence

The entries are stored in a Sqlite database file defined by the `database_file` configuration key. To disable persistance and use an in-memory keystore, use the special file `:memory:`.

### Configuration

(bi)bin is using [Rocket](https://rocket.rs/)'s configuration subsystem.
At startup it will read each key from a `Rocket.toml` file, or from environment variables (`ROCKET_` prefix)

```
[default]
password_hash = "OUTPUT OF cargo run --bin bibin_pwd_hash"
prefix = "https://YOUR.WEBSITE.net"
secret_key = "REPLACE WITH THE OUTPUT OF openssl rand -base64 32"
```

Optional entries:
```
address = "127.0.0.1"
port = "8000"
id_length = 4   # Size of the unique paste ID
max_entries = 10000   # Maximum number of paste kept in the database.
database_connections = 10    # Number of read-only connections to the DB opened in parallel
database_file=":memory:"    # Sqlite file on disk or ":memory:"
```

Override values from `Rocket.toml` with environment variables:
```
$ ROCKET_PREFIX="https://bi.bin" ROCKET_PASSWORD_HASH=<value from bibin_pwd_hash> ROCKET_ID_LENGTH=6 ./bibin
```

### Curl support

You can access the help by calling `/` with curl/wget/HTTPie:


```bash
$ curl https://YOUR.WEBSITE.net/

Hello and Welcome to the Curl interface

To add / delete / update a paste you will need to provide the password. Bibin support both
Basic authentication (any username but with the right password) and the X-API-Key token.


# Add a new paste
$ curl -X PUT -u "anything:YOUR_PASSWORD" --data 'hello world' https://YOUR.WEBSITE.net
# returns: https://YOUR.WEBSITE.net/cateettary

# Fetch a paste
$ curl https://YOUR.WEBSITE.net/cateettary
hello world

# Delete a paste
$ curl -X DELETE -H "X-API-Key:YOUR_PASSWORD" https://YOUR.WEBSITE.net/cateettary

# Upload a new paste at a given id. Would override any existing paste there.
$ curl -X PUT -u "anything:YOUR_PASSWORD" --data 'hello world' https://YOUR.WEBSITE.net/manualid
```

### What can bibin do?

**Scratchpad**: Everything that you write will be stored on your browser, so you can close the window and what you typed will be there again when you come back.

**Syntax highlighting**: you need to add the file extension at the end of your paste URL.

**URL Shortener**: the extension `.url` will trigger a http redirect to the url that is in the content. This works with curl requests as well!

**Other special extensions**:
- `.b64` will return the content base64-encoded
- `.qr` will return the content as a qr code

**Generate a QR code from the url**: Add `/qr` at the end of your bibin URL: `https://bi.bin/cateettary.c/qr`

**Expose text files for services**: Add `/raw` at the end of the bibin URL: `https://bi.bin/browser_blocklist.txt/raw`
