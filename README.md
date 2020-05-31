# smolsocket
SocketAddr based on smoltcp's IpAddress


There is no unspecified ip address as smoltcp's Address and IpEndpoint does.
It's more like the std SocketAddr but can be used in environments that std is not available.
