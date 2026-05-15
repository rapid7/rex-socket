# -*- coding: binary -*-
require 'rex/socket'

###
#
# This class provides methods for interacting with a UDP socket.
#
###
module Rex::Socket::Udp

  include Rex::Socket

  ##
  #
  # Factory
  #
  ##

  #
  # Creates the client using the supplied hash.
  #
  def self.create(hash = {})
    hash['Proto'] = 'udp'
    # If we have are to bind to a LocalHost we must be a Server to avail of pivoting.
    # Rex::Socket::Parameters will subsequently turn off the sever flag after the correct
    # comm has been chosen.
    if( hash['LocalHost'] )
      hash['Server'] = true
    end
    self.create_param(Rex::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base socket class' creation method that automatically
  # sets the parameter's protocol to UDP.
  #
  def self.create_param(param)
    param.proto = 'udp'
    Rex::Socket.create_param(param)
  end

  ##
  #
  # UDP connected state methods
  #
  ##

  #
  # Write the supplied datagram to the connected UDP socket.
  #
  def write(gram)
    begin
      return syswrite(gram)
    rescue  ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::EADDRNOTAVAIL
      return nil
    end
  end

  alias put write

  #
  # Read a datagram from the UDP socket.
  #
  def read(length = 65535)
    if length < 0
      length = 65535
    end
    return sysread(length)
  end

  #
  # Read a datagram from the UDP socket with a timeout
  #
  def timed_read(length = 65535, timeout=def_read_timeout)
    begin
      if ((rv = ::IO.select([ fd ], nil, nil, timeout)) and
          (rv[0]) and (rv[0][0] == fd)
         )
          return read(length)
      else
        return ''
      end
    rescue Exception
      return ''
    end
  end

  #alias send write
  #alias recv read

  ##
  #
  # UDP non-connected state methods
  #
  ##

  #
  # Sends a datagram to the supplied host:port with optional flags.
  #
  # @deprecated Use {#send} with the stdlib 4-arg form send(mesg, flags, host, port) instead.
  #   Note the argument order differs: sendto(gram, host, port, flags) vs send(mesg, flags, host, port).
  #
  def sendto(gram, peerhost, peerport, flags = 0)
    warn "#{self.class}#sendto is deprecated; use send(mesg, flags, host, port) instead", uplevel: 1
    send(gram, flags, peerhost, peerport)
  end

  #
  # Sends a datagram using the stdlib 4-arg form send(mesg, flags, host, port).
  #
  # The 4-arg form handles IPv6/IPv4 address mapping and dispatches via
  # BasicSocket#send with a packed sockaddr, so channel/pivoted sockets that
  # override sendto are not involved. Also accepts the 3-arg sockaddr form used
  # by lower-level callers, and the 2-arg connected-socket form.
  #
  def send(mesg, flags, host = nil, port = nil)
    if host && port
      # Catch unconnected IPv6 sockets talking to IPv4 addresses
      peer = Rex::Socket.resolv_nbo(host)
      if peer.length == 4 && self.ipv == 6
        host_address = Rex::Socket.getaddress(host, true)
        host = '::ffff:' + host_address unless host_address.downcase.start_with?('::ffff:')
      end
      begin
        super(mesg, flags, Rex::Socket.to_sockaddr(host, port))
      rescue ::Errno::EHOSTUNREACH, ::Errno::ENETDOWN, ::Errno::ENETUNREACH, ::Errno::ENETRESET,
             ::Errno::EHOSTDOWN, ::Errno::EACCES, ::Errno::EINVAL, ::Errno::EADDRNOTAVAIL
        nil
      end
    elsif host
      super(mesg, flags, host)
    else
      super(mesg, flags)
    end
  end

  #
  # Receives a datagram and returns the data and sender address information
  # as [ data, [address_family, port, host, host] ], matching the format of
  # stdlib UDPSocket#recvfrom (host appears in both the hostname and numeric
  # address positions; no reverse-DNS lookup is performed).
  #
  # @param maxlen [Integer] maximum number of bytes to receive
  # @param timeout [Numeric] seconds to wait before raising Errno::EAGAIN
  #   (default: def_read_timeout = 10). NOTE: this parameter was previously
  #   named +flags+ and defaulted to 0; callers that passed flags=0 explicitly
  #   will now receive a 0-second (poll) receive instead of a 10-second wait.
  #
  def recvfrom(maxlen, timeout = def_read_timeout)
    rv = ::IO.select([ fd ], nil, nil, timeout)

    raise Errno::EAGAIN, "Resource temporarily unavailable" if rv.nil?

    data, saddr = recvfrom_nonblock(maxlen)
    af, host, port = Rex::Socket.from_sockaddr(saddr)
    af_name = Socket.constants.grep(/^AF_/).find { |c| Socket.const_get(c) == af }.to_s
    [data, [af_name, port, host, host]]
  rescue ::Timeout::Error
    raise Errno::EAGAIN, "Resource temporarily unavailable"
  rescue ::Interrupt
    raise
  end

  #
  # Calls recvfrom and only returns the data
  #
  def get(timeout=nil)
    timed_read(65535, timeout)
  end

  #
  # The default number of seconds to wait for a read operation to timeout.
  #
  def def_read_timeout
    10
  end

  def type?
    return 'udp'
  end

end

