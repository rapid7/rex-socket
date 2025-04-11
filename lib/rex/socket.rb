# -*- coding: binary -*-
require 'rex/socket/version'
require 'socket'
require 'thread'
require 'resolv'
require 'rex/exceptions'
require 'dnsruby'

module Rex

###
#
# Base class for all sockets.
#
###
module Socket

  LogSource = 'rex-socket'

  module Comm
  end

  require 'rex/socket/x509_certificate'
  require 'rex/socket/parameters'
  require 'rex/socket/tcp'
  require 'rex/socket/tcp_server'

  require 'rex/socket/comm'
  require 'rex/socket/comm/local'

  require 'rex/socket/switch_board'
  require 'rex/socket/subnet_walker'
  require 'rex/socket/range_walker'

  ##
  #
  # Factory methods
  #
  ##

  #
  # Create a socket instance using the supplied parameter hash.
  #
  def self.create(opts = {})
    return create_param(Rex::Socket::Parameters.from_hash(opts))
  end

  #
  # Create a socket using the supplied Rex::Socket::Parameter instance.
  #
  def self.create_param(param)
    return param.comm.create(param)
  end

  #
  # Create a TCP socket using the supplied parameter hash.
  #
  def self.create_tcp(opts = {})
    return create_param(Rex::Socket::Parameters.from_hash(opts.merge('Proto' => 'tcp')))
  end

  #
  # Create a TCP server socket using the supplied parameter hash.
  #
  def self.create_tcp_server(opts = {})
    return create_tcp(opts.merge('Server' => true))
  end

  #
  # Create a UDP socket using the supplied parameter hash.
  #
  def self.create_udp(opts = {})
    return create_param(Rex::Socket::Parameters.from_hash(opts.merge('Proto' => 'udp')))
  end

  #
  # Create a IP socket using the supplied parameter hash.
  #
  def self.create_ip(opts = {})
    return create_param(Rex::Socket::Parameters.from_hash(opts.merge('Proto' => 'ip')))
  end


  #
  # Common Regular Expressions
  #

  # see: https://debugpointer.com/regex/regex-for-dns-name
  MATCH_DNS_NAME = /^(((?!-))(xn--)?([a-z0-9_][a-z0-9_\-]{0,59})?[a-z0-9_]\.)*(xn--)?([a-z0-9_\-]{1,61}|[a-z0-9_-]{1,30}\.[a-z]{2,})$/i

  MATCH_IPV6 = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/

  MATCH_IPV4 = /^\s*(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))\s*$/

  MATCH_IPV4_PRIVATE = /^\s*(?:10\.|192\.168|172.(?:1[6-9]|2[0-9]|3[01])\.|169\.254)/

  MATCH_MAC_ADDR = /^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/

  ##
  #
  # Serialization
  #
  ##

  # Cache our IPv6 support flag
  @@support_ipv6 = nil

  #
  # Determine whether we support IPv6
  #
  def self.support_ipv6?
    return @@support_ipv6 if not @@support_ipv6.nil?

    @@support_ipv6 = false

    if (::Socket.const_defined?('AF_INET6'))
      begin
        s = ::Socket.new(::Socket::AF_INET6, ::Socket::SOCK_DGRAM, ::Socket::IPPROTO_UDP)
        s.close
        @@support_ipv6 = true
      rescue
      end
    end

    return @@support_ipv6
  end

  #
  # Cache our resolver
  @@resolver = nil

  #
  # Determine whether this is a valid DNS name without trying to resolve it
  #
  def self.is_name?(name)
    return false if name.length > 253
    name.delete_suffix('.') =~ MATCH_DNS_NAME ? (name =~ /\s/).nil? : false
  end

  #
  # Determine whether this is an IPv4 address
  #
  def self.is_ipv4?(addr)
    addr =~ MATCH_IPV4 ? (addr =~ /\s/).nil? : false
  end

  #
  # Determine whether this is an IPv6 address
  #
  def self.is_ipv6?(addr)
    addr =~ MATCH_IPV6 ? (addr =~ /\s/).nil? : false
  end

  #
  # Determine whether this is a MAC address
  #
  def self.is_mac_addr?(addr)
    addr =~ MATCH_MAC_ADDR ? (addr =~ /\s/).nil? : false
  end

  #
  # Determine whether this is an IP address at all
  # Check for v4 (less expensive), v6, else false
  #
  def self.is_ip_addr?(addr)
    self.is_ipv4?(addr) || self.is_ipv6?(addr)
  end

  #
  # Checks to see if the supplied address is in "dotted" form
  #
  def self.dotted_ip?(addr)
    (support_ipv6? && self.is_ipv6?(addr)) || self.is_ipv4?(addr)
  end

  # Checks to see if an address is an IPv6 address and if so, converts it into its
  # square bracket format for addressing as noted in RFC 6874 which states that an IPv6
  # address literal in a URL is always embedded between [ and ]. Please also refer to
  # RFC5952, RFC3986, and RFC6874 for more info.
  #
  # RFC3986 section 3.2.2 specifically notes "A host identified by an Internet Protocol literal address, version 6
  # [RFC3513] or later, is distinguished by enclosing the IP literal
  # within square brackets ("[" and "]").  This is the only place where
  # square bracket characters are allowed in the URI syntax."
  #
  # RFC6874 reinforces this in section 2 where it notes "In a URI, a literal IPv6 address
  # is always embedded between '[' and ']'".
  #
  # @param host [String] IP address or hostname to convert to a URI authority.
  # @param port [Integer] Port number to include within the URI authority.
  # @return [String] Returns the URI authority string.
  # @raise [ArgumentError] This function will raise an ArgumentError if the host parameter is not a String.
  def self.to_authority(host, port=nil)
    unless host.kind_of?(String)
      raise ArgumentError.new("Expected a string for the host parameter!")
    end
    host = "[#{host}]" if is_ipv6?(host)
    host += ":#{port}" if port
    host
  end


  # Return true if +addr+ is within the ranges specified in RFC1918, or
  # RFC5735/RFC3927
  #
  def self.is_internal?(addr)
    self.dotted_ip?(addr) && addr =~ MATCH_IPV4_PRIVATE
  end

  # Get the first address returned by a DNS lookup for +hostname+.
  #
  # @see .getaddresses
  #
  # @param (see .getaddresses)
  # @return [String] ASCII IP address
  def self.getaddress(hostname, accept_ipv6 = true)
    getaddresses(hostname, accept_ipv6).first
  end

  #
  # Wrapper for +::Addrinfo.getaddrinfo+ that takes special care to see if the
  # supplied address is already an ASCII IP address.  This is necessary to
  # prevent blocking while waiting on a DNS reverse lookup when we already
  # have what we need.
  #
  # @param hostname [String] A hostname or ASCII IP address
  # @return [Array<String>]
  def self.getaddresses(hostname, accept_ipv6 = true)
    raise ::SocketError, 'getaddrinfo: nodename nor servname provided, or not known' if hostname.nil?

    if hostname =~ MATCH_IPV4 || (accept_ipv6 && hostname =~ MATCH_IPV6)
      return [hostname]
    end

    if @@resolver
      res = self.rex_getaddrinfo(hostname)
    else
      res = ::Addrinfo.getaddrinfo(hostname, 0, ::Socket::AF_UNSPEC, ::Socket::SOCK_STREAM)
    end

    res.map! do |address_info|
      address_info.ip_address
    end

    unless accept_ipv6
      res.reject! { |ascii| ascii =~ MATCH_IPV6 }
    end

    res
  end

  #
  # Wrapper for Socket.gethostbyname which takes into account whether or not
  # an IP address is supplied.  If it is, then reverse DNS resolution does
  # not occur.  This is done in order to prevent delays, such as would occur
  # on Windows.
  #
  # @deprecated Please use {#getaddress}, {#resolv_nbo}, or similar instead.
  def self.gethostbyname(host)
    warn "NOTE: #{self}.#{__method__} is deprecated, use getaddress, resolv_nbo, or similar instead. It will be removed in the next Major version"
    if is_ipv4?(host)
      return [ host, [], 2, host.split('.').map{ |c| c.to_i }.pack("C4") ]
    end

    if is_ipv6?(host)
      # pop off the scopeid since gethostbyname isn't smart enough to
      # deal with it.
      host, _ = host.split('%', 2)
    end

    @@resolver ? self.rex_gethostbyname(host) : ::Socket.gethostbyname(host)
  end

  #
  # Wrapper for Resolv::DNS.getresources which normalizes the return value to a
  # list of hostnames regardless of the resource class.
  #
  # @param name [String] The name to lookup.
  # @param typeclass [Symbol] The resource class to lookup, e.g. CNAME, MX, etc.
  # @raises ArgumentError An argument error is raised when the typeclass is invalid.
  # @return [Array<String>] The hostnames that were returned by the query.
  def self.getresources(name, typeclass)
    return self.rex_getresources(name, typeclass) if @@resolver

    typeclass = typeclass.upcase
    attribute = DNS_RESOURCE_ATTRIBUTE_NAMES[typeclass]
    if attribute.nil?
      raise ArgumentError, "Invalid typeclass: #{typeclass}"
    end
    const = Resolv::DNS::Resource::IN.const_get(typeclass)

    dns = Resolv::DNS.new
    resources = dns.getresources(name, const)
    resources.map(&attribute).map(&:to_s)
  end

  #
  # Create a sockaddr structure using the supplied IP address, port, and
  # address family
  #
  def self.to_sockaddr(ip, port)
    if ip == '::ffff:0.0.0.0'
      ip = support_ipv6?() ? '::' : '0.0.0.0'
    end

    return ::Socket.pack_sockaddr_in(port, ip)
  end

  #
  # Returns the address family, host, and port of the supplied sockaddr as
  # [ af, host, port ]
  #
  def self.from_sockaddr(saddr)
    port, host = ::Socket::unpack_sockaddr_in(saddr)
    af = ::Socket::AF_INET
    if support_ipv6?() && is_ipv6?(host)
      af = ::Socket::AF_INET6
    end
    return [ af, host, port ]
  end

  #
  # Resolves a host to raw network-byte order.
  #
  def self.resolv_nbo(host, accepts_ipv6 = true)
    ip_address = Rex::Socket.getaddress(host, accepts_ipv6)
    IPAddr.new(ip_address).hton
  end

  #
  # Resolves a host to raw network-byte order.
  #
  def self.resolv_nbo_list(host)
    Rex::Socket.getaddresses(host).map do |addresses|
      IPAddr.new(addresses).hton
    end
  end

  #
  # Resolves a host to a network-byte order ruby integer.
  #
  def self.resolv_nbo_i(host)
    addr_ntoi(resolv_nbo(host))
  end

  #
  # Resolves a host to a list of network-byte order ruby integers.
  #
  def self.resolv_nbo_i_list(host)
    resolv_nbo_list(host).map{|addr| addr_ntoi(addr) }
  end

  #
  # Converts an ASCII IP address to a CIDR mask. Returns
  # nil if it's not convertable.
  #
  def self.addr_atoc(mask)
    bits = is_ipv6?(mask) ? 128 : 32
    mask_i = resolv_nbo_i(mask)
    cidr = nil
    0.upto(bits) do |i|
      if ((1 << i)-1) << (bits - i) == mask_i
        cidr = i
        break
      end
    end
    return cidr
  end

  #
  # Resolves a CIDR bitmask into a dotted-quad. Returns
  # nil if it's not convertable.
  #
  def self.addr_ctoa(cidr, v6: false)
    bits = v6 ? 128 : 32
    cidr = cidr.to_i
    return nil unless (0..bits) === cidr
    addr_itoa(((1 << cidr)-1) << bits-cidr, v6)
  end

  #
  # Resolves a host to a dotted address.
  #
  def self.resolv_to_dotted(host)
    addr_ntoa(addr_aton(host))
  end

  #
  # Converts a ascii address into an integer
  #
  def self.addr_atoi(addr)
    resolv_nbo_i(addr)
  end

  #
  # Converts a ascii address into a list of addresses
  #
  def self.addr_atoi_list(addr)
    resolv_nbo_i_list(addr)
  end

  #
  # Converts an integer address into ascii
  #
  # @param (see #addr_iton)
  # @return (see #addr_ntoa)
  def self.addr_itoa(addr, v6=false)
    nboa = addr_iton(addr, v6)

    addr_ntoa(nboa)
  end

  #
  # Converts a ascii address to network byte order
  #
  def self.addr_aton(addr)
    resolv_nbo(addr)
  end

  #
  # Converts a network byte order address to ascii
  #
  # @param addr [String] Packed network-byte-order address
  # @return [String] Human readable IP address.
  def self.addr_ntoa(addr)
    # IPv4
    if (addr.length == 4)
      return addr.unpack('C4').join('.')
    end

    # IPv6
    if (addr.length == 16)
      return compress_address(addr.unpack('n8').map{ |c| "%x" % c }.join(":"))
    end

    raise RuntimeError, "Invalid address format"
  end

  #
  # Implement zero compression for IPv6 addresses.
  # Uses the compression method from Marco Ceresa's IPAddress GEM
  #
  # @see https://github.com/bluemonk/ipaddress/blob/master/lib/ipaddress/ipv6.rb
  #
  # @param addr [String] Human readable IPv6 address
  # @return [String] Human readable IPv6 address with runs of 0s removed
  def self.compress_address(addr)
    return addr unless is_ipv6?(addr)
    addr = addr.dup
    while true
      break if addr.sub!(/\A0:0:0:0:0:0:0:0\Z/, '::')
      break if addr.sub!(/\b0:0:0:0:0:0:0\b/, ':')
      break if addr.sub!(/\b0:0:0:0:0:0\b/, ':')
      break if addr.sub!(/\b0:0:0:0:0\b/, ':')
      break if addr.sub!(/\b0:0:0:0\b/, ':')
      break if addr.sub!(/\b0:0:0\b/, ':')
      break if addr.sub!(/\b0:0\b/, ':')
      break
    end
    addr.sub(/:{3,}/, '::')
  end

  #
  # Converts a network byte order address to an integer
  #
  def self.addr_ntoi(addr)

    bits = addr.unpack("N*")

    if (bits.length == 1)
      return bits[0]
    end

    if (bits.length == 4)
      val = 0
      bits.each_index { |i| val += (  bits[i] << (96 - (i * 32)) ) }
      return val
    end

    raise RuntimeError, "Invalid address format"
  end

  #
  # Converts an integer into a network byte order address
  #
  # @param addr [Numeric] The address as a number
  # @param v6 [Boolean] Whether +addr+ is IPv6
  def self.addr_iton(addr, v6=false)
    if(addr < 0x100000000 && !v6)
      return [addr].pack('N')
    else
      w    = []
      w[0] = (addr >> 96) & 0xffffffff
      w[1] = (addr >> 64) & 0xffffffff
      w[2] = (addr >> 32) & 0xffffffff
      w[3] = addr & 0xffffffff
      return w.pack('N4')
    end
  end

  #
  # Converts a colon-delimited MAC address into a 6-byte binary string
  #
  def self.eth_aton(mac)
    mac.split(":").map{|c| c.to_i(16) }.pack("C*")
  end

  #
  # Converts a 6-byte binary string into a colon-delimited MAC address
  #
  def self.eth_ntoa(bin)
    bin.unpack("C6").map{|x| "%.2x" % x }.join(":").upcase
  end

  #
  # Converts a CIDR subnet into an array (base, bcast)
  #
  def self.cidr_crack(cidr, v6=false)
    tmp = cidr.split('/')

    tst,scope = tmp[0].split("%",2)
    scope     = "%" + scope if scope
    scope   ||= ""

    addr = addr_atoi(tst)

    bits = 32
    mask = 0
    use6 = false

    if (addr > 0xffffffff or v6 or cidr =~ /:/)
      use6 = true
      bits = 128
    end

    mask = (2 ** bits) - (2 ** (bits - tmp[1].to_i))
    base = addr & mask

    stop = base + (2 ** (bits - tmp[1].to_i)) - 1
    return [self.addr_itoa(base, use6) + scope, self.addr_itoa(stop, use6) + scope]
  end

  #
  # Converts a netmask (255.255.255.240) into a bitmask (28).  This is the
  # lame kid way of doing it.
  #
  def self.net2bitmask(netmask)
    nmask = resolv_nbo(netmask)
    imask = addr_ntoi(nmask)
    bits  = 32

    if (imask > 0xffffffff)
      bits = 128
    end

    0.upto(bits-1) do |bit|
      p = 2 ** bit
      return (bits - bit) if ((imask & p) == p)
    end

    0
  end

  #
  # Converts a bitmask (28) into a netmask (255.255.255.240)
  #
  def self.bit2netmask(bitmask, ipv6=false)
    if bitmask > 32 or ipv6
      i = ((~((2 ** (128 - bitmask)) - 1)) & (2**128-1))
      n = Rex::Socket.addr_iton(i, true)
      return Rex::Socket.addr_ntoa(n)
    else
      [ (~((2 ** (32 - bitmask)) - 1)) & 0xffffffff ].pack('N').unpack('CCCC').join('.')
    end
  end


  def self.portspec_crack(pspec)
    portspec_to_portlist(pspec)
  end

  #
  # Converts a port specification like "80,21-25,!24,443" into a sorted,
  # unique array of valid port numbers like [21,22,23,25,80,443]
  #
  def self.portspec_to_portlist(pspec)
    ports = []
    remove = []

    # Build ports array from port specification
    pspec.split(/,/).each do |item|
      target = ports

      item.strip!

      if item.start_with? '!'
        item.delete! '!'
        target = remove
      end

      start, stop = item.split(/-/).map { |p| p.to_i }

      start ||= 0
      stop ||= item.match(/-/) ? 65535 : start

      start, stop = stop, start if stop < start

      start.upto(stop) { |p| target << p }
    end

    if ports.empty? and not remove.empty? then
      ports = 1.upto 65535
    end

    # Sort, and remove dups and invalid ports
    ports.sort.uniq.delete_if { |p| p < 1 or p > 65535 or remove.include? p }
  end

  #
  # Converts a port list like [1,2,3,4,5,100] into a
  # range specification like "1-5,100"
  #
  def self.portlist_to_portspec(parr)
    ranges = []
    range  = []
    lastp  = nil

    parr.uniq.sort{|a,b| a<=>b}.map{|a| a.to_i}.each do |n|
      next if (n < 1 or n > 65535)
      if not lastp
        range = [n]
        lastp = n
        next
      end

      if lastp == n - 1
        range << n
      else
        ranges << range
        range = [n]
      end
      lastp = n
    end

    ranges << range
    ranges.delete(nil)
    ranges.uniq.map{|x| x.length == 1 ? "#{x[0]}" : "#{x[0]}-#{x[-1]}"}.join(",")
  end

  ##
  #
  # Utility class methods
  #
  ##

  #
  # This method does NOT send any traffic to the destination, instead, it uses a
  # "bound" UDP socket to determine what source address we would use to
  # communicate with the specified destination. The destination defaults to
  # Google's DNS server to make the standard behavior determine which IP
  # we would use to communicate with the internet.
  #
  def self.source_address(dest='8.8.8.8', comm = ::Rex::Socket::Comm::Local)
    begin
      s = self.create_udp(
        'PeerHost' => dest,
        'PeerPort' => 31337,
        'Comm'     => comm
      )
      r = s.getsockname[1]

      # Trim off the trailing interface ID for link-local IPv6
      return r.split('%').first
    rescue ::Exception
      return '127.0.0.1'
    ensure
      s.close if s
    end
  end

  #
  # Identifies the link-local address of a given interface (if IPv6 is enabled)
  #
  def self.ipv6_link_address(intf)
    r = source_address("FF02::1%#{intf}")
    return nil if r.nil? || r !~ /^fe80/i
    r
  end

  #
  # Identifies the mac address of a given interface (if IPv6 is enabled)
  #
  def self.ipv6_mac(intf)
    r = ipv6_link_address(intf)
    return if not r
    raw = addr_aton(r)[-8, 8]
    (raw[0,3] + raw[5,3]).unpack("C*").map{|c| "%.2x" % c}.join(":")
  end

  #
  # Create a TCP socket pair.
  #
  # sf: This create a socket pair using native ruby sockets and will work
  # on Windows where ::Socket.pair is not implemented.
  # Note: OpenSSL requires native ruby sockets for its io.
  #
  # Note: Even though sub-threads are smashing the parent threads local, there
  #       is no concurrent use of the same locals and this is safe.
  def self.tcp_socket_pair
    lsock   = nil
    last_child_error = nil
    accept_timeout = 10
    rsock   = nil
    laddr   = '127.0.0.1'
    lport   = 0
    threads = []
    mutex   = ::Mutex.new

    threads << Rex::ThreadFactory.spawn('TcpSocketPair', false) do
      server = nil
      begin
        mutex.synchronize do
          threads << Rex::ThreadFactory.spawn('TcpSocketPairClient', false) do
            mutex.synchronize do
              begin
                rsock = ::TCPSocket.new( laddr, lport )
              rescue => e
                last_child_error = "#{e.class} - #{e.message}"
                raise
              end
            end
          end
          server = ::TCPServer.new(laddr, 0)
          if (server.getsockname =~ /127\.0\.0\.1:/)
            # JRuby ridiculousness
            caddr, lport = server.getsockname.split(":")
            caddr = caddr[1,caddr.length]
            lport = lport.to_i
          else
            # Sane implementations where Socket#getsockname returns a
            # sockaddr
            lport, caddr = ::Socket.unpack_sockaddr_in( server.getsockname )
          end
        end

        readable, _writable, _errors = ::IO.select([server], nil, nil, accept_timeout)
        if readable && readable.any?
          lsock, _ = server.accept_nonblock
        else
          raise RuntimeError, "rsock didn't connect in #{accept_timeout} seconds"
        end
      ensure
        server.close if server
      end
    end

    threads.each.with_index do |thread, i|
      thread.join
    rescue => e
      raise "Thread #{i} - error #{e} - last child error: #{last_child_error}"
    end

    return [lsock, rsock]
  end

  #
  # Create a UDP socket pair using native ruby UDP sockets.
  #
  def self.udp_socket_pair
    laddr = '127.0.0.1'

    lsock = ::UDPSocket.new
    lsock.bind( laddr, 0 )

    rsock = ::UDPSocket.new
    rsock.bind( laddr, 0 )

    rsock.connect( *lsock.addr.values_at(3,1) )

    lsock.connect( *rsock.addr.values_at(3,1) )

    return [lsock, rsock]
  end

  #
  # Install Rex::Proto::DNS::CachedResolver, or similar, to pivot DNS
  #
  # @param res [Rex::Proto::DNS::CachedResolver] Resolver object to handle DNS requests
  # @return [Rex::Proto::DNS::CachedResolver] The installed resolver
  def self._install_global_resolver(res)
    @@resolver = res
  end


  ##
  #
  # Class initialization
  #
  ##

  #
  # Initialize general socket parameters.
  #
  def initsock(params = nil)
    if (params)
      self.peerhost  = params.peerhost
      self.peerhostname = params.peerhostname
      self.sslkeylogfile = params.sslkeylogfile
      self.peerport  = params.peerport
      self.localhost = params.localhost
      self.localport = params.localport
      self.context   = params.context || {}
      self.ipv       = params.v6 ? 6 : 4
    end
  end

  #
  # By default, all sockets are themselves selectable file descriptors.
  #
  def fd
    self
  end

  #
  # Returns local connection information.
  #
  def getsockname
    Socket.from_sockaddr(super)
  end

  #
  # Wrapper around getsockname that stores the local address and local port values.
  #
  def getlocalname
    if [nil, '0.0.0.0', '::'].include?(self.localhost) && [nil, 0].include?(self.localport)
      _, self.localhost, self.localport = getsockname
    end

    family = Socket.is_ipv4?(self.localhost) ? ::Socket::AF_INET : ::Socket::AF_INET6
    [family, self.localhost, self.localport]
  end

  #
  # Returns peer connection information as an array.
  #
  def getpeername_as_array
    peer_name = nil
    begin
      peer_name = Socket.from_sockaddr(self.getpeername)
    rescue ::Errno::EINVAL => e
      # Ruby's getpeername method may call rb_sys_fail("getpeername(2)")
      elog("#{e.message} (#{e.class})#{e.backtrace * "\n"}\n", LogSource, LEV_3)
    end

    return peer_name
  end

  #
  # Returns peer information (host + port) in host:port format.
  #
  def peerinfo
    if (pi = getpeername_as_array)
      return pi[1] + ':' + pi[2].to_s
    end
  end

  #
  # Returns local information (host + port) in host:port format.
  #
  def localinfo
    if (pi = getlocalname)
      return pi[1] + ':' + pi[2].to_s
    end
  end

  #
  # Returns a string that indicates the type of the socket, such as 'tcp'.
  #
  def type?
    raise NotImplementedError, "Socket type is not supported."
  end

  #
  # The peer host of the connected socket.
  #
  attr_reader :peerhost
  #
  # The peer hostname of the connected socket.
  #
  attr_reader :peerhostname
  #
  # The SSL key log file path.
  #
  attr_reader :sslkeylogfile
  #
  # The peer port of the connected socket.
  #
  attr_reader :peerport
  #
  # The local host of the connected socket.
  #
  attr_reader :localhost
  #
  # The local port of the connected socket.
  #
  attr_reader :localport
  #
  # The IP version of the socket
  #
  attr_reader :ipv
  #
  # Contextual information that describes the source and other
  # instance-specific attributes.  This comes from the param.context
  # attribute.
  #
  attr_reader :context

protected

  attr_writer :peerhost, :peerhostname, :sslkeylogfile, :peerport, :localhost, :localport # :nodoc:
  attr_writer :context # :nodoc:
  attr_writer :ipv # :nodoc:

  #
  # @param name [String] The hostname to lookup via the resolver
  # @param resolver [Rex::Proto::DNS::CachedResolver] Resolver to query for the name
  # @return [Array] Array mimicking the native gethostbyname return type
  def self.rex_gethostbyname(name, resolver: @@resolver)
    v4, v6 = self.rex_resolve_hostname(name, resolver: resolver)
    # Build response array
    hostbyname = [name, []]
    unless v4.empty?
      hostbyname << ::Socket::AF_INET
      hostbyname += v4.map(&:address).map(&:address)
      hostbyname << v6[0].address.address unless v6.empty?
    else
      hostbyname << ::Socket::AF_INET6
      hostbyname += v6.map(&:address).map(&:address)
    end
    return hostbyname
  end

  #
  # @param name [String] The hostname to lookup via the resolver
  # @param resolver [Rex::Proto::DNS::CachedResolver] Resolver to query for the name
  # @return [Array] Array mimicking the native getaddrinfo return type
  def self.rex_getaddrinfo(name, resolver: @@resolver)
    v4_sockaddrs = []
    v6_sockaddrs = []

    if name =~ /\A\d+\Z/ && name.to_i.between?(0, 0xffffffff)
      v4_sockaddrs << self.to_sockaddr(name.to_i, 0)
    elsif name =~ /\A0x[0-9a-fA-F]+\Z/ && name.to_i(16).between?(0, 0xffffffff)
      v4_sockaddrs << self.to_sockaddr(name.to_i(16), 0)
    elsif self.is_ipv4?(name)
      v4_sockaddrs << self.to_sockaddr(name, 0)
    elsif self.is_ipv6?(name)
      v6_sockaddrs << self.to_sockaddr(name, 0)
    else
      v4, v6 = self.rex_resolve_hostname(name, resolver: resolver)
      v4.each do |a4|
        v4_sockaddrs << self.to_sockaddr(a4.address.to_s, 0)
      end
      v6.each do |a6|
        v6_sockaddrs << self.to_sockaddr(a6.address.to_s, 0)
      end
    end

    (v4_sockaddrs.map { |sa| [sa, ::Socket::AF_INET] } + v6_sockaddrs.map { |sa| [sa, ::Socket::AF_INET6] }).map do |sa, family|
      Addrinfo.new(sa, family, ::Socket::SOCK_STREAM, ::Socket::IPPROTO_TCP)
    end
  end


  # @param name [String] The hostname to lookup via the resolver
  # @param resolver [Rex::Proto::DNS::CachedResolver] Resolver to query for the name
  # @return [Array] Array of Dnsruby::Message responses for consumers to reformat
  def self.rex_resolve_hostname(name, resolver: @@resolver)
    raise ::SocketError.new(
      "Rex::Socket internal DNS resolution requires passing/setting a resolver"
    ) unless resolver
    raise ::SocketError.new(
      "Rex::Socket internal DNS resolution requires passing a String name to resolve"
    ) unless name.is_a?(String)
    # Pull both record types
    v4 = begin
      resolver.send(name, ::Dnsruby::Types::A).answer.select do |a|
        a.type == Dnsruby::Types::A
      end.sort_by do |a|
        self.addr_ntoi(a.address.address)
      end
    rescue StandardError
      []
    end
    v6 = begin
      resolver.send(name, Dnsruby::Types::AAAA).answer.select do |a|
        a.type == Dnsruby::Types::AAAA
      end.sort_by do |a|
        self.addr_ntoi(a.address.address)
      end
    rescue StandardError
      []
    end
    # Emulate ::Socket's error if no responses found
    if v4.empty? and v6.empty?
      raise ::SocketError.new('getaddrinfo: Name or service not known')
    end
    # Ensure response types (depending on underlying library used) provide required methods
    return v4, v6
  end

  def self.rex_getresources(name, typeclass, resolver: @@resolver)
    raise ::SocketError.new(
      "Rex::Socket internal DNS resolution requires passing/setting a resolver"
    ) unless resolver
    raise ::SocketError.new(
      "Rex::Socket internal DNS resolution requires passing a String name to resolve"
    ) unless name.is_a?(String)

    typeclass = typeclass.upcase
    attribute = REX_DNS_RESOURCE_ATTRIBUTE_NAMES[typeclass]
    if attribute.nil?
      raise ArgumentError, "Invalid typeclass: #{typeclass}"
    end
    const = Dnsruby::Types.const_get(typeclass)

    resources = begin
      resolver.send(name, const).answer.select do |a|
        a.type == const
      end.map(&attribute).map(&:to_s)
    rescue
      []
    end

    resources
  end

  DNS_RESOURCE_ATTRIBUTE_NAMES = {
    CNAME: :name,
    MX:    :exchange,
    NS:    :name,
    PTR:   :name,
    SOA:   :mname,
    SRV:   :target
  }.freeze
  private_constant :DNS_RESOURCE_ATTRIBUTE_NAMES

  REX_DNS_RESOURCE_ATTRIBUTE_NAMES = {
    CNAME: :domainname,
    MX:    :exchange,
    NS:    :domainname,
    PTR:   :domainname,
    SOA:   :mname,
    SRV:   :target
  }.freeze
  private_constant :REX_DNS_RESOURCE_ATTRIBUTE_NAMES
end

end

#
# Globalized socket constants
#
SHUT_RDWR = ::Socket::SHUT_RDWR
SHUT_RD   = ::Socket::SHUT_RD
SHUT_WR   = ::Socket::SHUT_WR
