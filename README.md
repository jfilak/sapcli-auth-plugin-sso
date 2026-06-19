# sapcli authentication plugin for Client Certificate SSO on Windows

This project ships an utility that makes a dummy HTTP request
over WinHTTP using Client Certififcate from user's certificate
store to establish a session with an ABAP system and then dump
the HTTP session cookies into starndard outout so
[sapcli](https://github.com/jfilak/sapcli) can use it communicate
over HTTP without the need to authenticate.

The trick is in using WinHTTP so the required certificate does not need
 to be exported from the Windows Certificate Store.

## Installation

Download the binary `sap-http-session-initializer.exe` from [Releases](https://github.com/jfilak/sapcli-auth-plugin-sso/releases). The Windows executable is automatically built and uploaded to releases using a GitHub workflow.

Make sure the binary `sap-http-session-initializer.exe` is not in
a temporary directory and remember its absolute path which you need
for configuration of `auth_plugin` in sapcli's config file.

## Usage

Update your `~/.sapcli/config.yml`

```yaml
connections:
  corporate-server:
    ashost: cool-dev-abap.example.org
    client: '100'
    port: 50001
    ssl: true
    sysnr: 00

users:
  sso-user:
    auth_plugin:
      command: C:\<absolute path>\sap-http-session-initializer.exe

contexts:
  corporate-sso:
    user: sso-user
    connection: corporate-server

current-context: corporate-sso
```

## Troubleshooting

If you open `certmgr.msc` you can see more certificates in
the folder Personal. Then you must specify the one which
should be used because `sap-htt-session-initializer` picks
the first one by default.

You can achieve that by specifying the certificates Subject
in `~/.sapcli/config.yml`.

```yaml
users:
  sso-user:
    auth_plugin:
      command: C:\<absolute path>\sap-http-session-initializer.exe
      parameters:
        cert_subject: <put the needed certificates name here>
```

First you should check your certificates:

```bash
sap-http-session-initializer.exe list-my-certs
```

The command shoud list the certificates in the format
that is used by the plugin to do the search.

```
CN=jakub@thefilaks.net, O=tinkers
CN=filak.jakub@gmail.net, O=talkers
```

Verify the choosen subject can be selected:

```bash
sap-http-session-initializer.exe find-my-certs "CN=filak.jakub@gmail.net, O=talkers"
```

Finally put it into the config file:

```yaml
users:
  sso-user:
    auth_plugin:
      command: C:\<absolute path>\sap-http-session-initializer.exe
      parameters:
        cert_subject: "CN=filak.jakub@gmail.net, O=talkers"
```