# -*- coding: binary -*-
require 'rex/socket'

###
#
# This class represents the set of parameters that are used to create
# a socket, whether it be a server or client socket.
#
# @example
#   nsock = Rex::Socket::Tcp.create(
#     'PeerHost'  =>  opts['RHOST'] || rhost,
#     'PeerPort'  => (opts['RPORT'] || rport).to_i,
#     'LocalHost' =>  opts['CHOST'] || chost || "0.0.0.0",
#     'LocalPort' => (opts['CPORT'] || cport || 0).to_i,
#     'SSL'       =>  dossl,
#     'SSLVersion'=>  opts['SSLVersion'] || ssl_version,
#     'Proxies'   => proxies,
#     'Timeout'   => (opts['ConnectTimeout'] || connect_timeout || 10).to_i,
#     'Context'   =>
#       {
#         'Msf'        => framework,
#         'MsfExploit' => self,
#       })
#
###
class Rex::Socket::Parameters

  ##
  #
  # Factory
  #
  ##

  #
  # Creates an instance of the Parameters class using the supplied hash.
  #
  def self.from_hash(hash)
    return self.new(hash)
  end

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the attributes from the supplied hash.  The following hash
  # keys can be specified.
  #
  # @option hash [String] 'PeerHost' The remote host to connect to
  # @option hash [String] 'PeerHostname' The unresolved remote hostname, used to specify Server Name Indication (SNI)
  # @option hash [String] 'PeerAddr' (alias for 'PeerHost')
  # @option hash [Fixnum] 'PeerPort' The remote port to connect to
  # @option hash [String] 'LocalHost' The local host to communicate from, if any
  # @option hash [String] 'LocalPort' The local port to communicate from, if any
  # @option hash [Bool] 'Bool' Create a bare socket
  # @option hash [Bool] 'Server' Whether or not this should be a server
  # @option hash [Bool] 'SSL' Whether or not SSL should be used
  # @option hash [OpenSSL::SSL::SSLContext] 'SSLContext' Use a pregenerated SSL Context
  # @option hash [String] 'SSLVersion' Specify Auto, SSL2, SSL3, or TLS1 (Auto is
  #   default)
  # @option hash [String] 'SSLCert' A file containing an SSL certificate (for
  #   server sockets)
  # @option hash [String] 'SSLCipher' see {#ssl_cipher}
  # @option hash [Bool] 'SSLCompression' enable SSL-level compression where available
  # @option hash [String] 'SSLVerifyMode' SSL certificate verification
  #   mechanism. One of 'NONE' (default), 'CLIENT_ONCE', 'FAIL_IF_NO_PEER_CERT ', 'PEER'
  # @option hash [String] 'Proxies' List of proxies to use.
  # @option hash [String] 'Proto' The underlying protocol to use.
  # @option hash [String] 'IPv6' Force the use of IPv6.
  # @option hash [String] 'Comm' The underlying {Comm} object to use to create
  #   the socket for this parameter set.
  # @option hash [Hash] 'Context' A context hash that can allow users of
  #   this parameter class instance to determine who is responsible for
  #   requesting that a socket be created.
  # @option hash [String] 'Retries' The number of times a connection should be
  #   retried.
  # @option hash [Fixnum] 'Timeout' The number of seconds before a connection
  #   should time out
  def initialize(hash = {})
    if (hash['PeerHost'])
      self.peerhost = hash['PeerHost']
    elsif (hash['PeerAddr'])
      self.peerhost = hash['PeerAddr']
    end

    if (hash['PeerHostname'])
      self.peerhostname = hash['PeerHostname']
    end

    if (hash['LocalHost'])
      self.localhost = hash['LocalHost']
    elsif (hash['LocalAddr'])
      self.localhost = hash['LocalAddr']
    end

    if (hash['PeerPort'])
      self.peerport = hash['PeerPort'].to_i
    end

    if (hash['LocalPort'])
      self.localport = hash['LocalPort'].to_i
    end

    if (hash['Bare'])
      self.bare = hash['Bare']
    end

    if (hash['SSL'] and hash['SSL'].to_s =~ /^(t|y|1)/i)
      self.ssl = true
    end

    if hash['SSLContext']
      self.sslctx = hash['SSLContext']
    end

    self.ssl_version = hash.fetch('SSLVersion', nil)

    supported_ssl_verifiers = %W{CLIENT_ONCE FAIL_IF_NO_PEER_CERT NONE PEER}
    if (hash['SSLVerifyMode'] and supported_ssl_verifiers.include? hash['SSLVerifyMode'])
      self.ssl_verify_mode = hash['SSLVerifyMode']
    end

    if hash['SSLCompression']
      self.ssl_compression = hash['SSLCompression']
    end

    if (hash['SSLCipher'])
      self.ssl_cipher = hash['SSLCipher']
    end

    if (hash['VHOST'])
      self.ssl_cn = hash['VHOST']
    end

    if (hash['SSLCommonName'])
      self.ssl_cn = hash['SSLCommonName']
    end

    if (hash['SSLCert'] and ::File.file?(hash['SSLCert']))
      begin
        self.ssl_cert = ::File.read(hash['SSLCert'])
      rescue ::Exception => e
        elog("Failed to read cert: #{e.class}: #{e}", LogSource)
      end
    end

    if (hash['SSLClientCert'] and ::File.file?(hash['SSLClientCert']))
      begin
        self.ssl_client_cert = ::File.read(hash['SSLClientCert'])
      rescue ::Exception => e
        elog("Failed to read client cert: #{e.class}: #{e}", LogSource)
      end
    end

    if (hash['SSLClientKey'] and ::File.file?(hash['SSLClientKey']))
      begin
        self.ssl_client_key = ::File.read(hash['SSLClientKey'])
      rescue ::Exception => e
        elog("Failed to read client key: #{e.class}: #{e}", LogSource)
      end
    end

    if hash['Proxies']
      self.proxies = hash['Proxies'].split(',').map{|a| a.strip}.map{|a| a.split(':').map{|b| b.strip}}
    end

    # The protocol this socket will be using
    if (hash['Proto'])
      self.proto = hash['Proto'].downcase
    end

    # Whether or not the socket should be a server
    self.server    = hash['Server']

    # The communication subsystem to use to create the socket
    self.comm      = hash['Comm']

    # The context that was passed in, if any.
    self.context   = hash['Context']

    # If we are a UDP server, turn off the server flag as it was only set when
    # creating the UDP socket in order to avail of the switch board above.
    if( self.server and self.proto == 'udp' )
      self.server = false
    end

    # The number of connection retries to make (client only)
    if hash['Retries']
      self.retries = hash['Retries'].to_i
    end

    # The number of seconds before a connect attempt times out (client only)
    if hash['Timeout']
      self.timeout = hash['Timeout'].to_i
    end

    # Whether to force IPv6 addressing
    if hash['IPv6'].nil?
      # if IPv6 isn't specified and at least one host is an IPv6 address and the
      # other is either nil, a hostname or an IPv6 address, then use IPv6
      self.v6 = (Rex::Socket.is_ipv6?(self.localhost) || Rex::Socket.is_ipv6?(self.peerhost)) && \
        (self.localhost.nil? || !Rex::Socket.is_ipv4?(self.localhost)) && \
        (self.peerhost.nil? || !Rex::Socket.is_ipv4?(self.peerhost))
    else
      self.v6 = hash['IPv6']
    end
  end

  def merge(other)
    self.dup.merge!(other)
  end

  def merge!(other)
    other = self.class.new(other) if other.is_a? Hash

    other.instance_variables.each do |name|
      value = other.instance_variable_get(name)
      instance_variable_set(name, value) unless value.nil?
    end
    self
  end

  ##
  #
  # Conditionals
  #
  ##

  #
  # Returns true if this represents parameters for a server.
  #
  def server?
    return (server == true)
  end

  #
  # Returns true if this represents parameters for a client.
  #
  def client?
    return (server == false)
  end

  #
  # Returns true if the protocol for the parameters is TCP.
  #
  def tcp?
    return (proto == 'tcp')
  end

  #
  # Returns true if the protocol for the parameters is UDP.
  #
  def udp?
    return (proto == 'udp')
  end

  #
  # Returns true if the protocol for the parameters is IP.
  #
  def ip?
    return (proto == 'ip')
  end

  #
  # Returns true if the socket is a bare socket that does not inherit from
  # any extended Rex classes.
  #
  def bare?
    return (bare == true)
  end

  #
  # Returns true if SSL has been requested.
  #
  def ssl?
    return ssl
  end

  #
  # Returns true if IPv6 has been enabled
  #
  def v6?
    return v6
  end

  ##
  #
  # Attributes
  #
  ##

  # The remote host information, equivalent to the PeerHost parameter hash
  # key.
  # @return [String]
  attr_accessor :peerhost

  # The remote hostname information, equivalent to the PeerHostname parameter hash
  # key.
  # @return [String]
  attr_accessor :peerhostname

  # The remote port.  Equivalent to the PeerPort parameter hash key.
  # @return [Fixnum]
  attr_writer :peerport
  def peerport
    @peerport || 0
  end

  # The local host.  Equivalent to the LocalHost parameter hash key.
  # @return [String]
  attr_writer :localhost
  def localhost
    return @localhost if @localhost

    if @v6 || (@peerhost && Rex::Socket.is_ipv6?(@peerhost))
      '::'
    else
      '0.0.0.0'
    end
  end

  # The local port.  Equivalent to the LocalPort parameter hash key.
  # @return [Fixnum]
  attr_writer :localport
  def localport
    @localport || 0
  end

  # The protocol to to use, such as TCP.  Equivalent to the Proto parameter
  # hash key.
  # @return [String]
  attr_writer :proto
  def proto
    @proto || 'tcp'
  end

  # Whether or not this is a server.  Equivalent to the Server parameter
  # hash key.
  # @return [Bool]
  attr_writer :server
  def server
    @server || false
  end

  # The {Comm} instance that should be used to create the underlying socket.
  # @return [Comm]
  attr_writer :comm
  def comm
    return @comm unless @comm.nil?

    best_comm = nil
    # If no comm was explicitly specified, try to use the comm that is best fit
    # to handle the provided host based on the current routing table.
    if server and localhost
      best_comm = Rex::Socket::SwitchBoard.best_comm(localhost)
    elsif peerhost
      best_comm =  Rex::Socket::SwitchBoard.best_comm(peerhost)
    end

    best_comm || Rex::Socket::Comm::Local
  end

  # The context hash that was passed in to the structure.  (default: {})
  # @return [Hash]
  attr_writer :context
  def context
    @context || {}
  end

  # The number of attempts that should be made.
  # @return [Fixnum]
  attr_writer :retries
  def retries
    @retries || 0
  end

  # The number of seconds before a connection attempt should time out.
  # @return [Fixnum]
  attr_writer :timeout
  def timeout
    @timeout || 5
  end

  # Whether or not this is a bare (non-extended) socket instance that should
  # be created.
  # @return [Bool]
  attr_writer :bare
  def bare
    @comm || false
  end

  # Whether or not SSL should be used to wrap the connection.
  # @return [Bool]
  attr_writer :ssl
  def ssl
    @ssl || false
  end

  # Pre configured SSL Context to use
  # @return [OpenSSL::SSL::SSLContext]
  attr_accessor :sslctx

  # What version of SSL to use (Auto, SSL2, SSL3, SSL23, TLS1)
  # @return [String,Symbol]
  attr_reader :ssl_version
  def ssl_version=(version)
    # Let the caller specify a particular SSL/TLS version
    case version
    when 'SSL2'
      version = :SSLv2
    # 'TLS' will be the new name for autonegotation with newer versions of OpenSSL
    when 'SSL23', 'TLS', 'Auto'
      version = :SSLv23
    when 'SSL3'
      version = :SSLv3
    when 'TLS1','TLS1.0'
      version = :TLSv1
    when 'TLS1.1'
      version = :TLSv1_1
    when 'TLS1.2'
      version = :TLSv1_2
    end

    @ssl_version = version
  end

  # What specific SSL Cipher(s) to use, may be a string containing the cipher
  # name or an array of strings containing cipher names e.g.
  # ["DHE-RSA-AES256-SHA", "DHE-DSS-AES256-SHA"]
  # @return [String,Array]
  attr_accessor :ssl_cipher

  # Which Common Name to use for certificate
  # @return [String}
  attr_accessor :ssl_cn

  # The SSL certificate, in pem format, stored as a string.  See
  # {Rex::Socket::SslTcpServer#makessl}
  # @return [String]
  attr_accessor :ssl_cert

  # Enables SSL/TLS-level compression
  # @return [Bool]
  attr_accessor :ssl_compression

  #
  # The client SSL certificate
  #
  attr_accessor :ssl_client_cert

  #
  # The client SSL key
  #
  attr_accessor :ssl_client_key

  #
  # SSL certificate verification mode for SSL context
  attr_accessor :ssl_verify_mode

  #
  # Whether we should use IPv6
  # @return [Bool]
  attr_writer :v6
  def v6
    @v6 || false
  end

  # List of proxies to use
  # @return [Array]
  attr_accessor :proxies

  alias peeraddr  peerhost
  alias localaddr localhost
end
