# smolsocket
SocketAddr based on smoltcp's IpAddress

[![CircleCI](https://circleci.com/gh/hlzhang/smolsocket.svg?style=shield)](https://circleci.com/gh/hlzhang/smolsocket)  [![Build Status](https://travis-ci.org/hlzhang/smolsocket.svg?branch=develop)](https://travis-ci.org/hlzhang/smolsocket)  [![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg)](https://opensource.org/licenses/Apache-2.0)  


There is no unspecified ip address as smoltcp's Address and IpEndpoint does.  
It's more like the std SocketAddr but can be used in environments that std is not available.  


```shell script
cargo test --no-default-features --features=proto-ipv4
cargo test --no-default-features --features=proto-ipv6
cargo test --no-default-features --features=proto-ipv4,proto-ipv6
cargo test --no-default-features --features=proto-ipv4,proto-ipv6,std
```

standard version
```shell script
npx standard-version --dry-run
```
