# netaddr package for go

This repo contains a library to complement the [go net library][net] and
provides containers and utilities like in python's [netaddr].

Please see the [api documentation] for details. [The authoritative source for
this library is found on github][source]. We encourage importing this code
using the stable, versioned URL provided by [gopkg.in][gopkg]. Once imported,
refer to it as `netaddr` in your code (without the version).

    import "gopkg.in/netaddr.v1"

## comparison with python's netaddr

This netaddr library was written to complement the existing [net] package in go
just filling in a few gaps that existed. See the table below for a side-by-side
comparison of python netaddr features and the corresponding features in this
library or elsewhere in go packages.

| Python netaddr | Go                                |
|----------------|-----------------------------------|
| EUI            | ???                               |
| IPAddress      | Use [IP] from [net]\*             |
| IPNetwork      | Use [IPNet] from [net]\*\*        |
| IPSet          | Use [IPSet]                       |
| IPRange        | Use [IPRange]                     |
| IPGlob         | Not yet implemented               |

\* The [net] package in golang parses IPv4 address as IPv4 encoded IPv6
addresses. I found this design choice frustrating. Hence, there is a [ParseIP]
in this package that always parses IPv4 as 4 byte addresses.

\*\* This package provides a few extra convenience utilities for [IPNet]. See
[ParseNet], [NetSize], [BroadcastAddr], and [NetworkAddr].

## help

This needs a lot of work. Help if you can!

- More test coverage

[netaddr]: https://netaddr.readthedocs.io/en/latest/installation.html
[net]: https://golang.org/pkg/net/
[api documentation]: https://godoc.org/gopkg.in/netaddr.v1
[source]: https://github.com/IBM/netaddr/
[gopkg]: https://gopkg.in/netaddr.v1
[IP]: https://golang.org/pkg/net/#IP
[IPNet]: https://golang.org/pkg/net/#IPNet
[IPSet]: https://godoc.org/gopkg.in/netaddr.v1#IPSet
[ParseIP]: https://godoc.org/gopkg.in/netaddr.v1#ParseIP
[ParseNet]: https://godoc.org/gopkg.in/netaddr.v1#ParseNet
[NetSize]: https://godoc.org/gopkg.in/netaddr.v1#NetSize
[BroadcastAddr]: https://godoc.org/gopkg.in/netaddr.v1#BroadcastAddr
[NetworkAddr]: https://godoc.org/gopkg.in/netaddr.v1#NetworkAddr
