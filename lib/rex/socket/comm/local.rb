# -*- coding: binary -*-
require 'singleton'
require 'rex/compat'
require 'rex/socket'
require 'rex/socket/tcp'
require 'rex/socket/ssl_tcp'
require 'rex/socket/ssl_tcp_server'
require 'rex/socket/udp'
require 'rex/socket/sctp'
require 'rex/socket/sctp_server'
require 'rex/socket/ip'
require 'rex/socket/proxies'
require 'timeout'

###
#
# Local communication class factory.
#
###
class Rex::Socket::Comm::Local

  include Singleton
  include Rex::Socket::Comm

  #
  # Creates an instance of a socket using the supplied parameters.
  #
  def self.create(param)

    # Work around jRuby socket implementation issues
    if(RUBY_PLATFORM == 'java')
      return self.create_jruby(param)
    end

    case param.proto
      when 'tcp'
        return create_by_type(param, ::Socket::SOCK_STREAM, ::Socket::IPPROTO_TCP)
      when 'udp'
        return create_by_type(param, ::Socket::SOCK_DGRAM, ::Socket::IPPROTO_UDP)
      when 'sctp'
        return create_by_type(param, ::Socket::SOCK_STREAM, ::Socket::IPPROTO_SCTP)
      when 'ip'
        return create_ip(param)
      else
        raise Rex::UnsupportedProtocol.new(param.proto), caller
    end
  end

  #
  # Creates an instance of a socket using the supplied parameters.
  # Use various hacks to make this work with jRuby
  #
  def self.create_jruby(param)
    sock = nil

    # Notify handlers of the before socket create event.
    self.instance.notify_before_socket_create(self, param)

    case param.proto
      when 'tcp'
        if param.server?
          sock  = TCPServer.new(param.localport, param.localhost)
          klass = Rex::Socket::TcpServer
          if param.ssl
            klass = Rex::Socket::SslTcpServer
          end
          sock.extend(klass)

        else
          sock = TCPSocket.new(param.peerhost, param.peerport)
          klass = Rex::Socket::Tcp
          if param.ssl
            klass = Rex::Socket::SslTcp
          end
          sock.extend(klass)
        end
      when 'udp'
        if param.server?
          sock = UDPServer.new(param.localport, param.localhost)
          klass = Rex::Socket::UdpServer
          sock.extend(klass)
        else
          sock = UDPSocket.new(param.peerhost, param.peerport)
          klass = Rex::Socket::Udp
          sock.extend(klass)
        end
      else
        raise Rex::UnsupportedProtocol.new(param.proto), caller
    end

    sock.initsock(param)
    self.instance.notify_socket_created(self, sock, param)
    return sock
  end


  #
  # Creates a raw IP socket using the supplied Parameter instance.
  # Special-cased because of how different it is from UDP/TCP
  #
  def self.create_ip(param)
    self.instance.notify_before_socket_create(self, param)

    sock = ::Socket.open(::Socket::PF_INET, ::Socket::SOCK_RAW, ::Socket::IPPROTO_RAW)
    sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_HDRINCL, 1)

    # Configure broadcast support
    sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_BROADCAST, true)

    if !param.bare?
      sock.extend(::Rex::Socket::Ip)
      sock.initsock(param)
    end

    self.instance.notify_socket_created(self, sock, param)

    sock
  end


  #
  # Creates a socket using the supplied Parameter instance.
  #
  def self.create_by_type(param, type, proto = 0)
    # Detect IPv6 addresses and enable IPv6 accordingly
    if Rex::Socket.support_ipv6?
      # Enable IPv6 dual-bind mode for unbound UDP sockets on Linux
      if type == ::Socket::SOCK_DGRAM && Rex::Compat.is_linux && !param.localhost && !param.peerhost
        param.v6 = true

      # Check if either of the addresses is 16 octets long
      elsif (param.localhost && Rex::Socket.is_ipv6?(param.localhost)) || (param.peerhost && Rex::Socket.is_ipv6?(param.peerhost))
        param.v6 = true
      end

      if param.v6
        if param.localhost && Rex::Socket.is_ipv4?(param.localhost)
          if Rex::Socket.addr_atoi(param.localhost) == 0
            param.localhost = '::'
          else
            param.localhost = '::ffff:' + param.localhost
          end
        end

        if param.peerhost && Rex::Socket.is_ipv4?(param.peerhost)
          if Rex::Socket.addr_atoi(param.peerhost) == 0
            param.peerhost = '::'
          else
            param.peerhost = '::ffff:' + param.peerhost
          end
        end
      end
    else
      # No IPv6 support
      param.v6 = false
    end

    # Notify handlers of the before socket create event.
    self.instance.notify_before_socket_create(self, param)

    # Create the socket
    sock = nil
    if param.v6
      sock = ::Socket.new(::Socket::AF_INET6, type, proto)
    else
      sock = ::Socket.new(::Socket::AF_INET, type, proto)
    end

    # Bind to a given local address and/or port if they are supplied
    if param.localport || param.localhost
      begin

        # SO_REUSEADDR has undesired semantics on Windows, instead allowing
        # sockets to be stolen without warning from other unprotected
        # processes.
        unless Rex::Compat.is_windows
          sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, true)
        end

        sock.bind(Rex::Socket.to_sockaddr(param.localhost, param.localport))

      rescue ::Errno::EADDRNOTAVAIL,::Errno::EADDRINUSE
        sock.close
        raise Rex::BindFailed.new(param.localhost, param.localport), caller
      end
    end

    # Configure broadcast support for all datagram sockets
    if type == ::Socket::SOCK_DGRAM
      sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_BROADCAST, true)
    end

    # If a server instance is being created...
    if param.server?
      sock.listen(256)

      if !param.bare?
        if param.proto == 'tcp'
          klass = Rex::Socket::TcpServer
          if param.ssl
            klass = Rex::Socket::SslTcpServer
          end
        elsif param.proto == 'sctp'
          klass = Rex::Socket::SctpServer
        else
          raise Rex::BindFailed.new(param.localhost, param.localport), caller
        end
        sock.extend(klass)

        sock.initsock(param)
      end
    # Otherwise, if we're creating a client...
    else
      # If we were supplied with host information
      if param.peerhost

        # A flag that indicates whether we need to try multiple scopes
        retry_scopes = false

        # Always retry with link-local IPv6 addresses
        if Rex::Socket.is_ipv6?( param.peerhost ) and param.peerhost =~ /^fe80::/
          retry_scopes = true
        end

        # Prepare a list of scope IDs to try when connecting to
        # link-level addresses. Read from /proc if it is available,
        # otherwise increment through the first 255 IDs.
        @@ip6_lla_scopes ||= []

        if @@ip6_lla_scopes.length == 0 and retry_scopes

          # Linux specific interface lookup code
          if ::File.exist?( "/proc/self/net/igmp6" )
            ::File.open("/proc/self/net/igmp6") do |fd|
              fd.each_line do |line|
                line = line.strip
                tscope, tint, junk = line.split(/\s+/, 3)
                next if not tint

                # Specifying lo in any connect call results in the socket
                # being unusable, even if the correct interface is set.
                next if tint == "lo"

                @@ip6_lla_scopes << tscope
              end
            end
          else
          # Other Unix-like platforms should support a raw scope ID
            [*(1 .. 255)].map{ |x| @@ip6_lla_scopes << x.to_s }
          end
        end

        ip6_scope_idx = 0

        if param.proxies?
          ip   = param.proxies.first.host
          port = param.proxies.first.port
        else
          ip   = Rex::Socket.getaddress(param.peerhost)
          port = param.peerport
        end

        begin

          begin
            Timeout.timeout(param.timeout) do
              sock.connect(Rex::Socket.to_sockaddr(ip, port))
            end
          rescue ::Timeout::Error
            raise ::Errno::ETIMEDOUT
          end

        rescue ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::ENOPROTOOPT

          # Rescue errors caused by a bad Scope ID for a link-local address
          if retry_scopes and @@ip6_lla_scopes[ ip6_scope_idx ]
            ip = param.peerhost + "%" + @@ip6_lla_scopes[ ip6_scope_idx ]
            ip6_scope_idx += 1
            retry
          end

          sock.close
          raise Rex::HostUnreachable.new(ip, port), caller

        rescue ::Errno::EADDRNOTAVAIL,::Errno::EADDRINUSE
          sock.close
          raise Rex::InvalidDestination.new(ip, port), caller

        rescue Errno::ETIMEDOUT
          sock.close
          raise Rex::ConnectionTimeout.new(ip, port), caller

        rescue ::Errno::ECONNRESET,::Errno::ECONNREFUSED,::Errno::ENOTCONN,::Errno::ECONNABORTED
          sock.close
          # Report the actual thing we were trying to connect to here, not
          # param.peerhost, since that's the eventual target at the end of the
          # proxy chain
          raise Rex::ConnectionRefused.new(ip, port.to_i), caller
        end
      end

      if !param.bare?
        case param.proto
          when 'tcp'
            klass = Rex::Socket::Tcp
            sock.extend(klass)
            sock.initsock(param)
          when 'udp'
            sock.extend(Rex::Socket::Udp)
            sock.initsock(param)
          when 'sctp'
            sock.extend(Rex::Socket::Sctp)
            sock.initsock(param)
        end
      end

      if param.proxies?
        param.proxies.each_cons(2) do |current_proxy, next_proxy|
          proxy(sock, current_proxy.scheme, next_proxy.host, next_proxy.port)
        end
        current_proxy = param.proxies.last
        proxy(sock, current_proxy.scheme, param.peerhost, param.peerport)
      end

      # Now extend the socket with SSL and perform the handshake
      if !param.bare? && param.ssl
        klass = Rex::Socket::SslTcp
        sock.extend(klass)
        sock.initsock(param)
      end
    end

    # Notify handlers that a socket has been created.
    self.instance.notify_socket_created(self, sock, param)

    sock
  end

  def self.proxy(sock, type, host, port)
    case type.downcase
    when Rex::Socket::Proxies::ProxyType::SAPNI
      packet_type = 'NI_ROUTE'
      route_info_version = 2
      ni_version = 39
      num_of_entries = 2
      talk_mode = 1 # ref: http://help.sap.com/saphelp_dimp50/helpdata/En/f8/bb960899d743378ccb8372215bb767/content.htm
      num_rest_nodes = 1

      _af, shost, sport = sock.getpeername_as_array
      first_route_item = [shost, 0, sport.to_s, 0, 0].pack("A*CA*cc")
      route_data = [first_route_item.length, first_route_item].pack("NA*")
      route_data << [host, 0, port.to_s, 0, 0].pack("A*CA*cc")

      ni_packet = [
        packet_type,
        0,
        route_info_version,
        ni_version,
        num_of_entries,
        talk_mode,
        0,
        0,
        num_rest_nodes
      ].pack("A8c8")
      # Add the data block, according to sap documentation:
      # A 4-byte header precedes each data block. These 4 bytes give the
      # length of the data block (length without leading 4 bytes)
      # The data block (the route data)
      ni_packet << [route_data.length - 4].pack('N') + route_data
      # Now that we've built the whole packet, prepend its length before writing it to the wire
      ni_packet = [ni_packet.length].pack('N') + ni_packet

      size = sock.put(ni_packet)

      if size != ni_packet.length
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end

      begin
        ret_len = sock.get_once(4, 30).unpack('N')[0]
        if ret_len and ret_len != 0
          ret = sock.get_once(ret_len, 30)
        end
      rescue IOError
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      if ret and ret.length < 4
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a complete response from the proxy"), caller
      end

      if ret =~ /NI_RTERR/
        case ret
        when /timed out/
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to remote host #{host} timed out")
        when /refused/
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to remote port #{port} closed")
        when /denied/
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to #{host}:#{port} blocked by ACL")
        else
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to #{host}:#{port} failed (Unknown fail)")
        end
      elsif ret =~ /NI_PONG/
        # success case
        # would like to print this "[*] remote native connection to #{host}:#{port} established\n"
      else
        raise Rex::ConnectionProxyError.new(host, port, type, "Connection to #{host}:#{port} failed (Unknown fail)")
      end

    when Rex::Socket::Proxies::ProxyType::HTTP
      setup = "CONNECT #{host}:#{port} HTTP/1.0\r\n\r\n"
      size = sock.put(setup)
      if size != setup.length
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end

      begin
        ret = sock.get_once(39,30)
      rescue IOError
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      if ret.nil?
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      resp = Rex::Proto::Http::Response.new
      resp.update_cmd_parts(ret.split(/\r?\n/)[0])

      if resp.code != 200
        raise Rex::ConnectionProxyError.new(host, port, type, "The proxy returned a non-OK response"), caller
      end
    when Rex::Socket::Proxies::ProxyType::SOCKS4
      supports_ipv6 = false
      setup = [4,1,port.to_i].pack('CCn') + Rex::Socket.resolv_nbo(host, supports_ipv6) + Rex::Text.rand_text_alpha(rand(8)+1) + "\x00"
      size = sock.put(setup)
      if size != setup.length
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end

      begin
        ret = sock.get_once(8, 30)
      rescue IOError
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      if ret.nil? || ret.length < 8
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a complete response from the proxy"), caller
      end
      if ret[1,1] != "\x5a"
        raise Rex::ConnectionProxyError.new(host, port, type, "Proxy responded with error code #{ret[0,1].unpack("C")[0]}"), caller
      end
    when Rex::Socket::Proxies::ProxyType::SOCKS5
      # follow the unofficial convention where SOCKS5 handles the resolution locally (which leaks DNS)
      if !Rex::Socket.is_ip_addr?(host)
        if !Rex::Socket.is_name?(host)
          raise Rex::ConnectionProxyError.new(host, port, type, "The SOCKS5 target host must be an IP address or a hostname"), caller
        end

        begin
          address = Rex::Socket.getaddress(host, Rex::Socket.support_ipv6?)
        rescue ::SocketError
          raise Rex::ConnectionProxyError.new(host, port, type, "The SOCKS5 target '#{host}' could not be resolved to an IP address"), caller
        end

        host = address
      end

      self.proxy_socks5h(sock, type, host, port)
    when Rex::Socket::Proxies::ProxyType::SOCKS5H
      # follow the unofficial convention where SOCKS5H has the proxy server resolve the hostname to and IP address
      self.proxy_socks5h(sock, type, host, port)
    else
      raise RuntimeError, "The proxy type specified is not valid", caller
    end
  end

  ##
  #
  # Registration
  #
  ##
  def self.register_event_handler(handler) # :nodoc:
    self.instance.register_event_handler(handler)
  end

  def self.deregister_event_handler(handler) # :nodoc:
    self.instance.deregister_event_handler(handler)
  end

  def self.each_event_handler(handler) # :nodoc:
    self.instance.each_event_handler(handler)
  end

  private

  def self.proxy_socks5h(sock, type, host, port)
    auth_methods = [5,1,0].pack('CCC')
    size = sock.put(auth_methods)
    if size != auth_methods.length
      raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller(1)
    end
    ret = sock.get_once(2,30)
    if ret[1,1] == "\xff"
      raise Rex::ConnectionProxyError.new(host, port, type, "The proxy requires authentication"), caller(1)
    end

    if Rex::Socket.is_ipv4?(host)
      accepts_ipv6 = false
      addr = Rex::Socket.resolv_nbo(host, accepts_ipv6)
      setup = [5,1,0,1].pack('C4') + addr + [port.to_i].pack('n')
    elsif Rex::Socket.is_ipv6?(host)
      raise Rex::RuntimeError.new('Rex::Socket does not support IPv6') unless Rex::Socket.support_ipv6?

      accepts_ipv6 = true
      addr = Rex::Socket.resolv_nbo(host, accepts_ipv6)
      setup = [5,1,0,4].pack('C4') + addr + [port.to_i].pack('n')
    else
      # Then it must be a domain name.
      setup = [5,1,0,3].pack('C4') + [host.length].pack('C') + host + [port.to_i].pack('n')
    end

    size = sock.put(setup)
    if size != setup.length
      raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller(1)
    end

    begin
      response = sock.get_once(10, 30)
    rescue IOError
      raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller(1)
    end

    if response.nil? || response.length < 10
      raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a complete response from the proxy"), caller(1)
    end
    if response[1,1] != "\x00"
      raise Rex::ConnectionProxyError.new(host, port, type, "Proxy responded with error code #{response[1,1].unpack("C")[0]}"), caller(1)
    end
  end
end
