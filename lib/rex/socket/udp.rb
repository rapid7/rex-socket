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
  # Receives a datagram and returns the data and sender address information as
  # [ data, [address_family, port, host, host] ], matching stdlib
  # UDPSocket#recvfrom. Like the stdlib method, this blocks until a datagram is
  # available and has no timeout of its own (see #timed_recvfrom for a variant
  # that does). The host appears in both the hostname and numeric address
  # positions; no reverse-DNS lookup is performed.
  #
  # @param maxlen [Integer] maximum number of bytes to receive
  # @param flags [Integer] flags passed to the underlying recvfrom(2) call (default: 0)
  # @return [Array(String, Array)] the datagram and the sender address information
  #
  def recvfrom(maxlen, flags = 0)
    # Block until the socket is readable to mirror the stdlib's blocking
    # UDPSocket#recvfrom; a nil timeout waits indefinitely.
    ::IO.select([ fd ], nil, nil, nil)
    data, saddr = recvfrom_nonblock(maxlen, flags)
    [ data, sender_addr_info(saddr) ]
  end

  #
  # Receives a datagram like #recvfrom but waits at most +timeout+ seconds for
  # one to arrive, returning nil if the timeout elapses first. The return value
  # otherwise matches #recvfrom: [ data, [address_family, port, host, host] ].
  #
  # @param maxlen [Integer] maximum number of bytes to receive
  # @param timeout [Numeric] seconds to wait for a datagram before giving up
  # @return [Array(String, Array), nil] the datagram and sender address
  #   information, or nil if no datagram arrived within +timeout+ seconds
  #
  def timed_recvfrom(maxlen = 65535, timeout = def_read_timeout)
    return nil unless ::IO.select([ fd ], nil, nil, timeout)

    data, saddr = recvfrom_nonblock(maxlen)
    [ data, sender_addr_info(saddr) ]
  rescue ::Timeout::Error
    nil
  end

  #
  # Converts a packed sockaddr into the stdlib UDPSocket#recvfrom-style sender
  # address tuple [ address_family, port, host, host ].
  #
  def sender_addr_info(saddr)
    af, host, port = Rex::Socket.from_sockaddr(saddr)
    af_name = ::Socket.constants.grep(/^AF_/).find { |c| ::Socket.const_get(c) == af }.to_s
    [ af_name, port, host, host ]
  end
  private :sender_addr_info

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

