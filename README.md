# CSPAuth[D] - Crude Single Packet Authorization [Daemon]

Single Packet Authorization (henceforth referenced as __SPA__) is a variation of common
[port-knocking](https://wiki.archlinux.org/title/Port_knocking) techniques which allows a
remote client to send a single, one-way packet to a SPA server to -- _traditionally_ -- open
access to one or more network services to all or certain specific source IP addresses.

CSPAuthD extends this functionality, by leveraging increasingly common user-managed PKI and
per-user authorization lists, to allow execution of any customized command sequence on the
SPA server according to parameters given directly or indirectly by the authenticated client.
Through this mechanism it still maintains the ability to grant access to a single network
resource, while also offering the flexibility of a predefined remote execution environment.

This repository package includes both the server software and its corresponding simple client
application. The combination of these two tools at both network endpoints unlocks the powerful
ability to execute predefined actions securely from any location.


## The Most Common Use-Case

If you're here to use SPA as a __pseudo-port-knocking__ function and that only, it's really
easy to set up despite all of the complexities below.

You can find my guide for setting up the port-knocking replacement -- for specifically Fedora
systems -- __here__.


## Terminology

Firstly, it's crucial to understand some quick terms in this document in order to proceed.

- `Action` - A command-string that the underlying system shell runs as the service user when a
  valid SPA packet is received by the server daemon. This string has the ability to dynamically
  expand some predefined tokens before handing off the command to the shell for execution.
- `Function` - A combination of `action:option`, where Action is the ID of the command-string to
  run, and Option is a specific ID to give to that Action. These two items put together represent
  a single "function".
- `User` - A simple string, not associated with any system user accounts (though they "can" be),
  which is associated to a public-key file and an authorization list.
- `Public Key` - Exactly what you think. A cryptographic key file that's one side of an asymmetric
  key pair, used by Users to sign outgoing SPA packet digests.
- `Authorization List` - Also called `AUTLs` here and there, these are per-user lists which grant
  access to certain functions as specified. ___All users are denied all functions unless otherwise
  specified by an AUTL definition.___


## How It Works

The server configuration, as verbose and long-winded as it looks, really boils down to __four__
critically-important values for getting SPAs through:

- `users` - A command-separated list (which can be specified multiple times) that denotes "user"
  objects who will have their own unique cryptographic keys and function authorizations.
- `pubkey:[user]` - Associates the full-path of the public key file to the username.
- `autl:[user]` - Associates the authorization list to the username.
- `action:[ID]` - Defines a command to pass to the underlying system shell for the given ID. The
  ID portion is the ID that's referenced in a client's "function" SPA request.

The simple breakdown for what happens when a SPA packet is received by the server is:
1. Check the timestamp against the server time, according to the `validity_window` setting.
2. Check the username and fetch her details.
3. Verify the packet hash is expected, and isn't a replay (if monitoring is enabled).
4. Validate the requested function against the user's authorization list.
5. Get the user's public key and verify the packet signature.
6. Grant authorization and perform the requested function.

With this in mind, setting up x509 certificates for use with the service and then delegating
authorized functions to certain users, who hold their respective key files, shouldn't seem much
of a hassle.

Once the user has a compatible client and their key, and they know their permitted functions,
they should be set to call them on the SPA server whenever they like. The configuration does
include a few possibly useful example actions that server administrators may be interested in.


#### Why Use IDs or Indexes?

As a side-note, some might ask, _"Why would you use ID numbers for calling these actions,
rather than allowing remote commands to be passed?"_

The response would be that a server administrator defining rigid "instructions" which are
directly granted to selected users, is so much simpler to manage, secure, and authorize
than directly allowing arbitrary commands to be passed to the underlying system shell.

---


## The SPA Protocol - "Crude"-style

CSPAuthD accepts its own (non-standard) UDP packets on its (also-non-standard) default bind
port of __41937__. The way it responds -- _if at all_ -- to client UDP packets is handled by
the `mode` setting within the daemon configuration.

The protocol is loosely based on a similar implementation from the well-known `fwknop` port-
knocking application, which has its own SPA functionality. Here's a breakdown of the raw
packet formatting and order:

| Field Name | Starting Position (byte) | Width (bytes) | Description |
| ----------- | ----------- | ----------- | ----------- |
| packet_data | 0 | 32 | Intended to be junk/random data, but could be used in `[[UNSAFE_DATA]]` action token expansions. |
| username | 32 | 16 | String representing the request's username, which associates to a local public key. |
| client_timestamp | 48 | QWORD | Epoch timestamp according to the client application/workstation. |
| request_action | 56 | WORD | The 16-bit Action portion of the requested function. |
| request_option | 58 | WORD | The 16-bit Option portion of the requested function. |
| __reserved | 60 | DWORD | Reserved space. Used to round packet fields to clean 2^x boundaries. |
| packet_hash | 64 | 32 | SHA256 packet digest of all the above fields. This digest is then signed (by another crypto digest function). |
| signature_length | 96 | DWORD | The length of this SPA packet's trailing cryptographic signature. |
| packet_signature | 100 | 1 to 2,048 | The cryptographic SHA256 signature using the private cryptographic key associated with the `username` above. |


## Other Details

Many of the other operational application details can be found in the project's sample
configuration file, which will need to be ___fully reviewed and understood___ before using
the server daemon.

---


## SPA Server Daemon

The SPA server is designed to operate as a system service which logs key details to the local
syslog server/application, based on the `log_level` setting per the loaded configuration. It's
made to run with the lowest memory footprint possible, and keeps a best-effort policy to collect
heap garbage as it can.

Each incoming packet that's being tracked is associated with a randomly-generated 64-bit
identifier in its syslog details. The ID allows the full activity of that specific packet to be
closely tracked, monitored, and analyzed.

Users can choose to let the daemon run as root or restrict it with a `sudo`-privileged user (if
that's desired at all).

By default, the RPM for Fedora systems installs the daemon as the `root` user. ___As such, it's
very important to read the configuration closely and not to leave any potential for the root user
to perform malicious functions.___ This is intended to change in the future, but for now the
`root` user is the default run-level on installation.


## Installing the Server

To install the server on Fedora-based Linux systems (_where it's been primarily tested_), simply
download the available RPM version __here__ and install it as `root` or with `sudo` per the
guide below.

```
# Install the package
[root@server1 ~]# rpm -ivh cspauth.rpm
. . .
. . .

# Enable the service and boot-time and start it now
[root@server1 ~]# systemctl enable --now cspauthd.service
. . .

# View SPA server daemon logs
[root@server1 ~]# journalctl -rt cspauthd
. . .
. . .

```

---

## Using the CSPAuth Client

Usage information for the client application can be found by executing the program without any
parameters. Its usage details are not here statically since it will change as the application
evolves. Rest assured, the client is fairly quick to get working for most Linux users.

If a custom client is created following the packet specification above, that's an even better
solution that can be tailored to custom use-cases!

---


## Building from Source

The whole project can easily be built with `GCC` in a few different ways, using the convenient
Makefile build directives.

__Build the Optimized Release Version__ :tm: :
```
make release
```

__Build the Debugging Version__:
```
make clean ; make all
```

When using the __debugging__ version (if debugging is your specific goal), don't forget to
always initialize the CLI application with the `debug` flag, like so:
```
[root@server1 cspauth]# make clean ; make all
. . .
. . .

[root@server1 cspauth]# ./bin/cspauthd -x
. . .
. . .
```

To build the client and server applications independently:
```
make clean ; make client/server
```

---


## Feedback

Please feel free to provide direct feedback or feature suggestions on this project as you'd
like! I'm always very open to adding or changing parts of a project to suit wider audiences or
to foster a great community.

Thank you for reading, and enjoy!
