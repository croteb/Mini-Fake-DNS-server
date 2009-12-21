require 'socket'
include Socket::Constants

class DNSQuery
  def initialize(data)
    @data=data
    puts data.inspect
    @dominio=''
    a = data[2]
    a = a.ord
    a =  a >> 3
    tipo = a & 15   # Opcode bits
    if tipo == 0:                     # Standard query
      ini=12
      lon = data[ini]
      lon = lon.ord
      while lon != 0:
        puts data[ini+1..ini+lon+1]
        @dominio+=data[ini+1..ini+lon+1].pack('C*')+'.'
        ini+=lon+1
        lon = data[ini]
        lon = lon.ord
      end
    end
  end

  def respuesta(ip)
    packet=Array.new
    if @dominio
      packet << @data[0..1] 
      packet << "\x81\x80".unpack("C2")
      packet << @data[4..5] 
      packet << @data[4..5]
      packet << "\x00\x00\x00\x00".unpack("C4")   # Questions and Answers Counts
      puts packet.inspect
      packet << @data[12..@data.length]                                        # Original Domain Name Question
      packet << "\xc0\x0c".unpack('C2')                                             # Pointer to domain name
      packet << "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04".unpack("C10")            # Response type, ttl and resource data length -> 4 bytes
      packet << ip.split('.').map {|x| x.to_i}
    end
    packet = packet.flatten
    return packet.pack("C*")
  end
end

class UDPServer
  def initialize(port)
    @port = port
  end

  def start
    @socket = UDPSocket.new
    @socket.bind('127.0.0.1', @port)
    puts 'DNS Bound'
    while true
      packet,sender = @socket.recvfrom(1024)
      packet = packet.unpack("C*")
      a = DNSQuery.new(packet)
      resp = a.respuesta("192.168.1.1")
      puts resp.inspect
      @socket.send(resp,0,sender[3],sender[1])
    end
  end
end

server = UDPServer.new(53)
server.start

