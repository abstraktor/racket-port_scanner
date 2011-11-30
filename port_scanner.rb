#!/usr/bin/env ruby

# this is a multithreading portscanner for tcp connection scanning and stealth syn scanning
# Bastian Kruck (ich@bkruck.de)

# built with mri ruby 1.8.7 on ubuntu with racket, bit-struct and pcaprub
# for exact versions, see Gemfile.lock


require 'thread'
require 'monitor'

require 'rubygems'
require 'pcaprub'
require 'racket'
require 'socket'

require 'tcp_scan'
require 'syn_scan'

IFACE = "eth0" # sorry to hardcode this, but I spent to much time for debugging racket

# I require that src_ip because racket renders the wrong checksum when using the "0.0.0.0" for local ip. isn't that incredible?
# this took me about 10 hours to find this issue
# see the definition of compute_checksum in racket at http://spoofed.org/files/racket/src/lib/racket/l4/tcp.rb

SRC_IP = ARGV[0]

# help him
abort "usage: #{$0} <src_ip> <dst_ip> {syn|con} [optional: port]" if ARGV.count < 3

# what kind of scan do we do?
case ARGV[2]
  when 'syn'  then scan = SynScan
  when 'con'  then scan = TcpScan
  else        abort 'syn OR con!'
end


if ARGV[3]
  # scan a single port
  scan.new(ARGV[1].to_s, ARGV[3].to_i)
else
  # scan all ports
  cnt = 0
  1.upto(65535) do |dst_port|
    t = Thread.new do
      scan.new(ARGV[1].to_s, dst_port)
    end

    # don't stress the systems too much
    sleep 0.1
  end
end
