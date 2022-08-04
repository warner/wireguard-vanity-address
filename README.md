# wireguard-vanity-address

Generate Wireguard keypairs with a given prefix string.

[![Build Status][build-status-image]][build-status-url]
[![Deps][deps-status-image]][deps-status-url]
[![Is-It-Maintained-Resolution-Time][iim-resolution-image]][iim-resolution-url]
[![Is-It-Maintained-Open-Issues][iim-open-image]][iim-open-url]
[![Crates.io][crates-io-image]][crates-io-url]
[![Docs.rs][docs-image]][docs-url]
[![License][license-image]][license-url]

[build-status-image]: https://travis-ci.org/warner/wireguard-vanity-address.svg?branch=master
[build-status-url]: https://travis-ci.org/warner/wireguard-vanity-address
[deps-status-image]: https://deps.rs/repo/github/warner/wireguard-vanity-address/status.svg
[deps-status-url]: https://deps.rs/repo/github/warner/wireguard-vanity-address
[crates-io-image]: https://img.shields.io/crates/v/wireguard-vanity-address.svg
[crates-io-url]: https://crates.io/crates/wireguard-vanity-address
[docs-image]: https://docs.rs/wireguard-vanity-address/badge.svg
[docs-url]: https://docs.rs/wireguard-vanity-address
[license-image]: https://img.shields.io/crates/l/wireguard-vanity-address.svg
[license-url]: LICENSE
[iim-resolution-image]: http://isitmaintained.com/badge/resolution/warner/wireguard-vanity-address.svg
[iim-resolution-url]: http://isitmaintained.com/project/warner/wireguard-vanity-address
[iim-open-image]: http://isitmaintained.com/badge/open/warner/wireguard-vanity-address.svg
[iim-open-url]: http://isitmaintained.com/project/warner/wireguard-vanity-address

The [Wireguard VPN](https://www.wireguard.com/) uses Curve25519 keypairs, and
displays the Base64-encoded public key in status displays. I found it hard to
remember which key goes with which target, and the config file doesn't really
support comments or attaching human-memorable names to those keys.

So this tool lets you generate a few million keypairs and print out just the
ones with a given string in the first few (10) letters, using a
case-insensitive search to increase your chances.

## Usage

```
$ cargo install wireguard-vanity-address
$ wireguard-vanity-address dave

searching for 'dave' in pubkey[0..10], one of every 149796 keys should match
one trial takes 17.9 us, CPU cores available: 4
est yield: 671.4 ms per key, 1.49 keys/s
hit Ctrl-C to stop
private cG8SfQGIK4dKZcjtFaVZT3ws7rFfwaaicborQz0IBWA=  public E6cRdAve5NmLpoH1nXjJqcVJRz9sM7cbeK4xaxYsH3o=
private OEkbz37Ztn3Y8R1cfPRHiB9wTA6av/NRzGUuO4hxAnE=  public 0Vr/JZDAve8q+kmNVmiw4KdKiXc//M0EGOY6K9C11nw=
private 8GBLlDECKxTk7VeZ4Mn9zQxUR+lyBzsijczQr6RjE2Y=  public QU8cNLDaVeoqLsyzKx9pFnSN4GNQMkG16TnS4e0XwFU=
private +KmScBxM3iAfIGkqwNYmngRqDq7I1T/P7tH4SNcnqXY=  public 0VvjqadaVeruKrpTc67tuqs2fi3qcP800u5RF3G9fz8=
private gHM5OIUCcecxJg/LIvCGTiMz6UzvZ0Q3V0QW7ngj3FI=  public gjEILdAvEfvG9Ncr14NqeRQrmT5ZJBIrbS+6FsOBiEM=
private QGeuFWwFsCsVrVd39Yp1ItnUicyjwgkjZpvY9npE5F4=  public 6IxmSDave735au9+saEYiB+azvSBIHWfnqCWa9tI5CU=
private OHIZd5auDHQzMFC+r3fp2pF4sstg5SQJjd9bG+QldUo=  public DAVemWOQZBonokPo7H1jiM61STpRUNYv0N0q27Uztgg=
private UDXTYKg2yL/fjc/ces3QVorAKZnHCJm2NBTP6h9bU2Q=  public UBWDAvEwBARXYvkwsUwFVwgFoV230/0Eir+xFWR6kGU=
private EJN1n9o3ilXW7yBPt49vNJe00NK2w6TABETX0z/o124=  public SSDAvEjMO/FpizG3/8rYqDYKFfX7no8ydi+tRrHM9ls=
private KBnvZZ/2T+NkWzI/FODyU5P6DpA7vC/kO9d0ZiMODlE=  public 5OWaDAVEf1xzoiUomAdyCe4MI0x/XjXciqcm7rinhnQ=
private SKE/SnG41wDgDBlEuqRpYd2UnXDph1+6cvENDd/W00o=  public XU0daveTtUZAxFpfPSrfZqp+Yv/EqXGuoSOS15iUUh8=
private eHa22XAJYBj6PxhSkeI5BO71j3/CC9yLeM8zKyzdUV0=  public XDaVEaxYDwPmcAMGlP8CzMEnGC7oSGW3AURF5anC5gA=
private 6Ojic3AYJFgCBIAwExBY74kOKLciJWRkXB17jTfvuWk=  public LdaVewaFPZFHV+5SGNwNdAUJjyVVyprVQs/fDuE5SR8=
private +Hw5k1ABvrYJRoRwGizFhwP5sJcowv4pTii/V7dJ4lA=  public HVyDAvEia/j/pBMx/1mxdsCDprAjZf1U3K0Fn9zEfVk=
private wNVk0Y2LDEmpcNyBIOtmco87v+9hdquSKFnOYyyfY2Y=  public kdavEA7x1CduyJ9+WpfDF5QG1ZSOI4NiduVBTAniB0Y=
private kPCNY3QiCsOLakmh8CPsu6QPMW3MtkFwKP+HKDsOpnA=  public daVE11aF7bx40NqwQqV14hxydDwiv4rC0JPhEVxAKnM=
...
```

The tool will run for a long time, printing out more and more candidates as
it goes, so just interrupt the process with Control-C or SIGINT when you've
seen something that you like. There is no saved state or config file, and the
generation process is entirely memoryless, so you don't lose any progress by
interrupting it.

Once you've found a key that you like, copy the private half (on the left)
into your `wg0.conf` config file as the `[Interface] PrivateKey=` field, and
use the public half (on the right) on the other side of that VPN connection
in a `[Peer] PublicKey=` entry.

## Performance

On my 2017 laptop (quad-core 2.8GHz), this tool checks about 60 thousand keys
per second per core. It uses [rayon](https://crates.io/crates/rayon) to
parallelize across all available cores, achieving 240k keys per second.

Only a tiny fraction of those trial keys will match the search string. Each
character of the target string reduces this fraction by a factor of about 32
(case-folded base64 encoding). By allowing the match to start anywhere in the
first ten letters, we increase the hit rate by about 10x.

A four-character string like `dave` means only one out of every (roughly)
150k keys will match, while a five-character string like `carol` reduces that
to one out of 5.6 million. Longer strings will yield fewer candidate keypairs
for a given amount of runtime.

You can run this on multiple machines, but of course you then risk revealing
your private VPN key to any of those machines. There is no support for
managing clusters or anything like that: just install the tool on each worker
machine and run it with the same argument.

Since Wireguard VPN keys are not really public identifiers (you wouldn't
publish them on a web page as you might with Tor's "Onion Addresses", or
Bitcoin addresses), my advice is to stick with a four or five character
search string, and don't try too hard to find a perfect pubkey. You only need
something distinctive enough distinguish between a handful of VPN targets in
a status display.

## Dockerfile

This repo contains a Dockerfile for running the binary so you
don't have to install rust or other build tools.
To use it:

```
docker build -t wgvanity .          # to build the container

docker run --rm --init -it wgvanity "string"   # string for the "vanity address"
```
After you find a suitable public key (with a good vanity address),
hit Control-C to abort 

## License

This is distributed under the MIT license,
see [LICENSE](LICENSE.md) for details.
