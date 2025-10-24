# -*- coding: binary -*-
require 'rex/socket'
require 'rex/socket/ssl'
require 'rex/socket/tcp_server'
require 'rex/io/stream_server'

###
#
# This class provides methods for interacting with an SSL wrapped TCP server.  It
# implements the StreamServer IO interface.
#
###
module Rex::Socket::SslTcpServer

  include Rex::Socket::Ssl
  include Rex::Socket::TcpServer

  ##
  #
  # Factory
  #
  ##

  def self.create(hash = {})
    hash['Proto']  = 'tcp'
    hash['Server'] = true
    hash['SSL']    = true
    self.create_param(Rex::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base class' creation method that automatically sets
  # the parameter's protocol to TCP and sets the server flag to true.
  #
  def self.create_param(param)
    param.proto  = 'tcp'
    param.server = true
    param.ssl    = true
    Rex::Socket.create_param(param)
  end

  def initsock(params = nil)

    if params && params.sslctx && params.sslctx.kind_of?(OpenSSL::SSL::SSLContext)
      self.sslctx = params.sslctx
    else
      self.sslctx  = makessl(params)
    end

    super
  end

  # (see TcpServer#accept)
  def accept(opts = {})
    sock = super()
    return if not sock

    begin
      ssl = OpenSSL::SSL::SSLSocket.new(sock, self.sslctx)

      if not allow_nonblock?(ssl)
        begin
          Timeout::timeout(3.5) {
            ssl.accept
          }
        rescue ::Timeout::Error => e
          sock.close
          raise ::OpenSSL::SSL::SSLError
        end
      else
        begin
          ssl.accept_nonblock

        rescue ::IO::WaitReadable
          IO::select( [ self.sslsock ], nil, nil, 0.10 )
          retry

        rescue ::IO::WaitWritable
          IO::select( nil, [ self.sslsock ], nil, 0.10 )
          retry
        end
      end

      sock.extend(Rex::Socket::SslTcp)
      sock.sslsock = ssl
      sock.sslctx  = self.sslctx

      return sock

    rescue ::OpenSSL::SSL::SSLError
      sock.close
      nil
    end
  end

end

