require 'monitor'
require 'pcaprub'
require 'racket'

ERR_NEED_ROOT = "Execute me as root! I need to bypass your operating systems network stack!\nYou might want to do: \n\trvmsudo %s %s" %[$0, $*.join(" ")]

#this is a threadsafe, stealth syn-scan
class SynScan < Monitor

  # lets bypass the os network stack and build custom packets with racket
  include Racket

  def initialize(dst_ip, port)

    abort ERR_NEED_ROOT if Process.uid != 0 # care for root rights

    @dst_ip = dst_ip
    @port = port 
    @@timeout = 2

    open_listener # ok let's start listening at first to ensure we 'hear' the response
    send          # send the actual syn package
    listen        # wait for an answer or timeout to happen and handle the result
  end

  # start capture with pcaprub
  def open_listener
    @listener = PCAPRUB::Pcap.open_live(IFACE, 65535, false, 1)
    @listener.setfilter("tcp port #{@port} and tcp[tcpflags] & tcp-ack != 0")
  end

  def send
    @p = Racket.new
    @p.iface = IFACE

    @p.l3 = L3::IPv4.new
    @p.l3.src_ip = SRC_IP
    @p.l3.dst_ip = @dst_ip
    @p.l3.protocol = 6
    @p.l3.ttl = 64
	
    @p.l4 = L4::TCP.new
    @p.l4.src_port = next_src_port
    @p.l4.dst_port = @port
    @p.l4.flag_syn = 1
    #p.l4.window = 2048

    # build checksum and length fields
    @p.l4.fix!(@p.l3.src_ip, @p.l3.dst_ip, "") # last param for next payload

    # just send the packet
    @p.sendpacket
  end

  def listen

    t = 0
    # wait for an answer or the timeout
    until data=@listener.next or t==@@timeout do
      sleep 0.3
      t += 1
    end

    return if t==@@timeout  # timeout! this does not fit to the RFCs. Should we retry it or ignore?
    
    # build a packet out of these raw data (ip starts at 14)
    p3 = L3::IPv4.new(data[14,data.length])

    # tcp lays on ip
    p4 = L4::TCP.new(p3.payload)

    # evaluate whether this is what I'm waiting for 
    if p4.src_port==@port and p3.src_ip==@dst_ip then
      puts @port if p4.flag_syn==1 and p4.flag_ack==1 #this is the only answer conforming to the RFCs
    else
      listen #this is not, what I'm waiting for. continue waiting!
    end
  end

  # well this gives some variation to the process so that the computers don't get bored
  def next_src_port
    1024 + rand(65535 - 1024)
  end

end