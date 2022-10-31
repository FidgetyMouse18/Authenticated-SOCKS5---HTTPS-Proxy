# Authenticated SOCKS5 & HTTPS Proxy

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Use and Licensing](#use)

## About <a name = "about"></a>

An implementation of the HTTP/s and SOCKS5 proxy protocols with custom authentication. Authentication can be granted, revoked modified from http endpoints using a given 32 byte security key.

## Getting Started <a name = "getting_started"></a>

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Installing

Before compiling, please be sure to set the security key in the constants of [Proxy.go](Proxy.go). You can also optionally change the ports used.

Simply Compile the code

```
go build ./proxy.go
```

You can then manually launch or use a server file similar to the example provided in [Proxy.service](Proxy.service).

### HTTP Endpoints
There are 3 endpoints used for managing the list of currently authenticated users
- add
- remove
- modify

All 3 have AES encrypted data passed to them using the security key and specified as the url param "data" and are formatted as following:
- add: username:hashed_password:security_key
- remove: username:security_key
- modify: username:new_hashed_password:security_key

#### Notes
For add and remove, the action is applied to the specific ip the request was made to (all in use ip's have these endpoints). 

Additionally, the sent hashed password should use sha256 for hashing.

## Use and Licensing <a name = "use"></a>
This software is free to modify and use for personal and educational purposes so long as credit is given. Commercial or monetary use requires explicit permission from myself with arrangements.