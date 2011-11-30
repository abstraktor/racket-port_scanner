installation
============
use ruby 1.8.7
```bundle install``` to install the required gems

usage
============
	./port_scanner.rb <src_ip> <dst_ip> {syn or con} [optional: port]

examples  
============
	rvmsudo ./port_scanner.rb 172.16.4.53 141.89.64.1 syn
	./port_scanner.rb 172.16.4.53 141.89.64.1 con 22

documentation
===========
see doc/index.html


troubleshooting
===============
use ```rvmsudo``` for syn-scanning if you use rvm