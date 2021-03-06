go-snmp-proxy
=============

![CI](https://github.com/grongor/go-snmp-proxy/workflows/CI/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/grongor/go-snmp-proxy/badge.svg)](https://coveralls.io/github/grongor/go-snmp-proxy)

HTTP proxy server for SNMP requests, written in Go.

Use cases
---------

- reduce time for devices with latency issues (remote locations, bad connection, ...)
  - fetching large SNMP tree of a server in Asia from data center in US might take a long time
- remove dependency on SNMP from your code
  - don't want to/can't install SNMP tooling, PHP extension,... ? This solves it gracefully.
- use HTTP authentication for your SNMP requests
- encrypt "SNMP traffic" between the client and the server
- bypass firewall
- ...post your use-case via issue/PR :-)

Only SNMP versions 1 and 2c are supported. If you want support for version 3, please, send a pull request.

Clients
=======

| Language | Link                               |
|----------|------------------------------------|
| PHP      | https://github.com/simPod/PHP-SNMP |

Feel free to create an issue to include your implementation here.

How it works
------------

The application provides a single HTTP endpoint `/snmp-proxy`, which accepts POST requests:
```json
{
    "host": "192.168.1.1",
    "community": "public",
    "version": "2c",
    "timeout": 10,
    "retries": 3,
    "requests": [
        {
            "request_type": "getNext",
            "oids": [
                ".1.2.3",
                ".4.5.6"
            ]
        },
        {
            "request_type": "walk",
            "oids": [".7.8.9"],
            "max_repetitions": 20
        }
    ]
}
```

It will then issue SNMP requests based on the given JSON request, convert the result into JSON and send it back
to the client. Response might look like this:
```json
{
    "result": [
        [
            ".1.2.3.4.5",
            123,
            ".4.5.6.7.8",
            "lorem"
        ],
        [
            ".7.8.9.1.1",
            "some",
            ".7.8.9.1.2",
            "values",
            ".7.8.9.1.3",
            "here"
        ]
    ]
}
```

Result is an array instead of a map because maps in Go aren't ordered (and overcoming this would unnecessarily
complicated), and the order is also not guaranteed by the JSON format.

If there is an error, response will be as follows:
```json
{
    "error": "description of what happened"
}
```

Some errors are "standardized" and expected:
 - no such instance
 - no such object
 - end of mib

The rest of the errors just describe what unexpected happened.

MIBs
----

The application will try to find all installed MIBs and parse the DisplayHint information for OctetString types
so that it knows how to format them. MIB parsing was inspired by
[Prometheus SNMP exporter generator](https://github.com/prometheus/snmp_exporter/tree/master/generator). Thanks!

In case that OID is of the type OctetString, and it isn't found in the MIBs, then we try to detect whether the string
is printable (utf8 valid + all characters are printable). If it isn't, it's formatted as `AB C0 D5 D6...`.

MIBs parsing can be skipped by using a binary built with `-tags=nonetsnmp`.
These binaries are also available in the [Releases](https://github.com/grongor/go-snmp-proxy/releases).

Metrics
-------

If you set Metrics.Listen address in the config, the application will expose Prometheus metrics on given address[:port],
specifically on `GET /metrics`. These metrics contain all essential information about Go runtime, and a histogram
of `POST /snmp-proxy` requests (count, durations).

Shared libraries
----------------

Unless you use binary built with `-tags=nonetsnmp`, you will have to install a shared library for the `snmp-proxy`:
`libsnmp` (contained in `libsnmp-dev`).

Binaries available in the [Releases](https://github.com/grongor/go-snmp-proxy/releases) will be built on the Ubuntu LTS
and thus compatible with the version of this library available in the Ubuntu LTS (and stable Debian).
If that doesn't match your target system, you can:
 - install the expected version of `libsnmp` (you will usually have the newer version, but it should be possible
   to install older one)
 - build the `snmp-proxy` yourself in the same environment as you expected the `snmp-proxy` to run
 - use binary built with `-tags=nonetsnmp`, also available in the
   [Releases](https://github.com/grongor/go-snmp-proxy/releases)
