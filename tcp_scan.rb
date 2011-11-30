require 'monitor'
require 'socket'

# this is a threadsafe tcp-connection scan
class TcpScan < Monitor

  # just try to open a socket and handle the result
  def initialize(dst_ip, port)
    @s = TCPSocket.new(dst_ip, port)
  rescue Errno::ECONNREFUSED, Errno::EISCONN
    return
  else 
    @s.close
    puts port
  end

end