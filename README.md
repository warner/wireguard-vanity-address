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

prefix: dave, expect 174762 trials, Ctrl-C to stop
private IdNXJiaM7tOj98OiieDd2xRbu8yf7kiiR3pk4SWMEEE=  public yr2JDaVe6ZK1vkHywqpDCMrsGNc8d+nA6elF18noUSw=
private /whCdWznKwYp0RmceUkoom5cDLTr31Lu+f1kH1jY/eg=  public uhmietdaVevBpy3OkMHlDLVHPgted8OVea/RdPK8Fzc=
private cyFsWAmV8Glxu5VJb8w6VfMcYVjenHncqFfw9AAjQfE=  public HomPjDAVEWAiPRjpwIOlL3lANxLl+Fght830T1aIgSY=
private qt14HDWqCpgSXHg2VcaI1TH5TfFj6oT1JAVmrw62tvQ=  public vCDaverGJfgg6iuBsQSl70Fre7QGdWVe47cuDEBommg=
private sNd1lYl3AVEQLdefxzaHGc0gEs+tfzNGEbf/T7jC+iA=  public Uo2bDAveso7KODCdqmlgfb8pRBREEr+awT0XAHfrLEs=
private 3+Go1RFaej19xEBPtHejZjOPjl/7hrBam8ntpka62rM=  public p25Dave1avsdf2kqe5N9ba5l68l/P5UIfjx5DVa/HB0=
private vkHRP/xkKXYSLO9uKmzhSXxlxi/9Bnw+jbIu2rIU1Ok=  public jdaVEP1sWbWZgP53EN1xLTCWDOhu0FdDIS5KkPIuNBY=
private 1CJUJqyQugbi1nOViLxrQaOW6acr72Bju452UXJH1Fs=  public bdaveYuRDXZTSzJvhCEgjl+7cCqtycndj938A9Y9nVg=
private hz28Klx8T/s8HuEk2IemdwXvO39dUlEw5fiDJnK67Xc=  public IxMTDaVEVLIZxQYsvsEmRqN75Z6xjSLr2PLvaFh4HG8=
private uayw2nhmAy/3MR6g76wd3QzrcTg2Ar6c2hckaBQxRmQ=  public 1/daveL3RqKwctapADasRFXdPsRe9mDpnDlk7gQJ+Hk=
private nCLdMw3Hglekgq8HtbnUBU/x+Kf2gFRmMI25L7d8Cyw=  public VudaVEpJ9eetGMtwzTuGjzzdLjCzy3IvlWT1M2lKTCI=
private de/p5FYlr/k0gR+ZxuQc6AiqdCpHNdpqLW/vT2DmX0o=  public gdAVewkiOCGxBTaKQnxxXGxvI3Bi4seGEWQu0dd28RI=
private zQ1zsL78zXpcsC2sTic9NO1ra6M3TvV7Dmr0qB673Vo=  public IB7DavEQlPTQsFX5KbhZ8mxFUXtgFM8uz7kOVvcL+0Q=
private K67utiFzOC83X9JxHIg+e/iLMMpCm+1KnH8eNAcwweY=  public bDAve2MMDgfsmgzeebFEGJakHAHzFoVwiauojGD8RCs=
private 7GIB3Y/cRQQRsP5h1zfzV+Ln4cYo0B8aUKkLvteZ+ew=  public zkiFOdaVea1r2EFaWtg9yt9xrAzn/csF3/VuduiJGCs=
private jWCtWfGdQLtmwTG6RWc0Dlx4oXM909WT4tWQYRpmR9A=  public YuKadaveihLt1pRi5tGiLzLSetLlTwcwfR315LINpDQ=
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
(case-folded base64 encoding). By allowing the match to occur anywhere in the
first ten letters, we increase the hit rate by about 10x.

A four-character string like `dave` means only one out of every (roughly)
100k keys will match, while a five-character string like `carol` reduces that
to one out of 3.3 million. Longer strings will yield fewer candidate keypairs
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

## License

This is distributed under the MIT license, see [LICENSE](LICENSE.md) for
details.
