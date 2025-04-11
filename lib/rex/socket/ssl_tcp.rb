# -*- coding: binary -*-
require 'rex/socket'
require 'openssl'
###
#
# This class provides methods for interacting with an SSL TCP client
# connection.
#
###
module Rex::Socket::SslTcp

begin

  include Rex::Socket::Tcp

  ##
  #
  # Factory
  #
  ##

  #
  # Creates an SSL TCP instance.
  #
  def self.create(hash = {})
    hash['SSL'] = true
    self.create_param(Rex::Socket::Parameters.from_hash(hash))
  end

  #
  # Set the SSL flag to true,
  # create placeholders for client certs,
  # call the base class's create_param routine.
  #
  def self.create_param(param)
    param.ssl   = true
    Rex::Socket::Tcp.create_param(param)
  end

  ##
  #
  # Class initialization
  #
  ##

  def self.system_ssl_methods
    ssl_context = OpenSSL::SSL::SSLContext
    if ssl_context.const_defined? :METHODS_MAP
      ssl_context.const_get(:METHODS_MAP).keys
    else
      ssl_context::METHODS
    end
  end

  def self.supported_ssl_methods
    @@methods ||= ['Auto', 'TLS'] + system_ssl_methods
      .reject { |method| method.match(/server|client/) }
      .select {|m| OpenSSL::SSL::SSLContext.new(m) && true rescue false} \
      .map {|m| m.to_s.sub(/v/, '').sub('_', '.')}
  end

  #
  # Initializes the SSL socket.
  #
  def initsock(params = nil)
    super

    version = params&.ssl_version || Rex::Socket::Ssl::DEFAULT_SSL_VERSION
    # Raise an error if no selected versions are supported
    unless Rex::Socket::SslTcp.system_ssl_methods.include? version
      raise ArgumentError,
        "This version of Ruby does not support the requested SSL/TLS version #{version}"
    end

    # Try initializing the socket with this SSL/TLS version
    # This will throw an exception if it fails
    initsock_with_ssl_version(params, version)

    # Track the SSL version
    self.ssl_negotiated_version = version
  end

  def initsock_with_ssl_version(params, version)
    # Build the SSL connection
    self.sslctx  = OpenSSL::SSL::SSLContext.new(version)

    # writing to the sslkeylogfile is required, it adds support for network capture decryption which is useful to
    # decrypt TLS traffic in wireshark
    if sslkeylogfile
      unless self.sslctx.respond_to?(:keylog_cb)
        raise 'Unable to create sslkeylogfile - Ruby 3.2 or above required for this functionality'
      end

      self.sslctx.keylog_cb = proc do |_sock, line|
        File.open(sslkeylogfile, 'ab') do |file|
          file.write("#{line}\n")
        end
      end
    end

    # Configure client certificate
    if params and params.ssl_client_cert
      self.sslctx.cert = OpenSSL::X509::Certificate.new(params.ssl_client_cert)
    end

    # Configure client key
    if params and params.ssl_client_key
      self.sslctx.key = OpenSSL::PKey::RSA.new(params.ssl_client_key)
    end

    # Configure the SSL context
    # TODO: Allow the user to specify the verify mode callback
    # Valid modes:
    #  VERIFY_CLIENT_ONCE
    #  VERIFY_FAIL_IF_NO_PEER_CERT
    #  VERIFY_NONE
    #  VERIFY_PEER
    if params.ssl_verify_mode
      self.sslctx.verify_mode = OpenSSL::SSL.const_get("VERIFY_#{params.ssl_verify_mode}".intern)
    else
      # Could also do this as graceful faildown in case a passed verify_mode is not supported
      self.sslctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
    end

    self.sslctx.options = OpenSSL::SSL::OP_ALL
    self.sslctx.options |= OpenSSL::SSL::OP_LEGACY_SERVER_CONNECT

    if params.ssl_cipher
      self.sslctx.ciphers = params.ssl_cipher
    end

    # Set the verification callback
    self.sslctx.verify_callback = Proc.new do |valid, store|
      self.peer_verified = valid
      true
    end

    # Tie the context to a socket
    self.sslsock = OpenSSL::SSL::SSLSocket.new(self, self.sslctx)

    # If peerhostname is set, or if hostname looks like a hostname, set the undocumented 'hostname'
    # attribute on sslsock, which enables the Server Name Indication (SNI)
    # extension
    if self.peerhostname and not self.peerhostname.strip.empty?
      self.sslsock.hostname = self.peerhostname
    elsif !Rex::Socket.dotted_ip?(self.peerhost)
      self.sslsock.hostname = self.peerhost
    end

    # Force a negotiation timeout
    begin
    Timeout.timeout(params.timeout) do
      if not allow_nonblock?
        self.sslsock.connect
      else
        begin
          self.sslsock.connect_nonblock
        # Ruby 1.8.7 and 1.9.0/1.9.1 uses a standard Errno
        rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
            IO::select(nil, nil, nil, 0.10)
            retry

        # Ruby 1.9.2+ uses IO::WaitReadable/IO::WaitWritable
        rescue ::Exception => e
          if ::IO.const_defined?('WaitReadable') and e.kind_of?(::IO::WaitReadable)
            IO::select( [ self.sslsock ], nil, nil, 0.10 )
            retry
          end

          if ::IO.const_defined?('WaitWritable') and e.kind_of?(::IO::WaitWritable)
            IO::select( nil, [ self.sslsock ], nil, 0.10 )
            retry
          end

          raise e
        end
      end
    end

    rescue ::Timeout::Error
      raise Rex::ConnectionTimeout.new(params.peerhost, params.peerport)
    end
  end

  ##
  #
  # Stream mixin implementations
  #
  ##

  #
  # Writes data over the SSL socket.
  #
  def write(buf, opts = {})
    return sslsock.write(buf) if not allow_nonblock?

    total_sent   = 0
    total_length = buf.length
    block_size   = 16384
    retry_time   = 0.5

    begin
      while( total_sent < total_length )
        s = Rex::ThreadSafe.select( nil, [ self.sslsock ], nil, 0.25 )
        if( s == nil || s[0] == nil )
          next
        end
        data = buf[total_sent, block_size]
        sent = sslsock.write_nonblock( data )
        if sent > 0
          total_sent += sent
        end
      end

    rescue ::IOError, ::Errno::EPIPE
      return nil

    # Ruby 1.8.7 and 1.9.0/1.9.1 uses a standard Errno
    rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
      # Sleep for a half a second, or until we can write again
      Rex::ThreadSafe.select( nil, [ self.sslsock ], nil, retry_time )
      # Decrement the block size to handle full sendQs better
      block_size = 1024
      # Try to write the data again
      retry

    # Ruby 1.9.2+ uses IO::WaitReadable/IO::WaitWritable
    rescue ::Exception => e
      if ::IO.const_defined?('WaitReadable') and e.kind_of?(::IO::WaitReadable)
        IO::select( [ self.sslsock ], nil, nil, retry_time )
        retry
      end

      if ::IO.const_defined?('WaitWritable') and e.kind_of?(::IO::WaitWritable)
        IO::select( nil, [ self.sslsock ], nil, retry_time )
        retry
      end

      # Another form of SSL error, this is always fatal
      if e.kind_of?(::OpenSSL::SSL::SSLError)
        return nil
      end

      # Bubble the event up to the caller otherwise
      raise e
    end

    total_sent
  end

  #
  # Polls the stream to see if there is any read data available.  Returns
  # true if data is available for reading, otherwise false is returned.
  #
  def has_read_data?(timeout = nil)
    return true if self.sslsock.pending > 0

    # Allow a timeout of "0" that waits almost indefinitely for input, this
    # mimics the behavior of Rex::ThreadSafe.select() and fixes some corner
    # cases of unintentional no-wait timeouts.
    timeout = 3600 if (timeout and timeout == 0)

    begin
      s = Rex::ThreadSafe.select( [ self.sslsock ], nil, nil, timeout )
      return !( s == nil || s[0] == nil )
    rescue ::Errno::EBADF, ::Errno::ENOTSOCK
      raise ::EOFError
    rescue ::Rex::StreamClosedError, ::IOError, ::EOFError, ::Errno::EPIPE
      #  Return false if the socket is dead
      return false
    end
  end

  #
  # Reads data from the SSL socket.
  #
  def read(length = nil, opts = {})
    if not allow_nonblock?
      length = 16384 unless length
      begin
        return sslsock.sysread(length)
      rescue ::IOError, ::Errno::EPIPE, ::OpenSSL::SSL::SSLError
        return nil
      end
      return
    end


    begin
      while true
        s = Rex::ThreadSafe.select( [ self.sslsock ], nil, nil, 0.10 )
        if( s == nil || s[0] == nil )
          next
        end
        return sslsock.read_nonblock( length )
      end

    rescue ::IOError, ::Errno::EPIPE
      return nil

    # Ruby 1.8.7 and 1.9.0/1.9.1 uses a standard Errno
    rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
      # Sleep for a tenth a second, or until we can read again
      Rex::ThreadSafe.select( [ self.sslsock ], nil, nil, 0.10 )
      # Decrement the block size to handle full sendQs better
      block_size = 1024
      # Try to write the data again
      retry

    # Ruby 1.9.2+ uses IO::WaitReadable/IO::WaitWritable
    rescue ::Exception => e
      if ::IO.const_defined?('WaitReadable') and e.kind_of?(::IO::WaitReadable)
        IO::select( [ self.sslsock ], nil, nil, 0.5 )
        retry
      end

      if ::IO.const_defined?('WaitWritable') and e.kind_of?(::IO::WaitWritable)
        IO::select( nil, [ self.sslsock ], nil, 0.5 )
        retry
      end

      # Another form of SSL error, this is always fatal
      if e.kind_of?(::OpenSSL::SSL::SSLError)
        return nil
      end

      raise e
    end

  end


  #
  # Closes the SSL socket.
  #
  def close
    sslsock.close rescue nil
    super
  end

  #
  # Ignore shutdown requests
  #
  def shutdown(how=0)
    # Calling shutdown() on an SSL socket can lead to bad things
    # Cause of http://metasploit.com/dev/trac/ticket/102
  end

  #
  # Access to peer cert
  #
  def peer_cert
    sslsock.peer_cert if sslsock
  end

  #
  # Access to peer cert chain
  #
  def peer_cert_chain
    sslsock.peer_cert_chain if sslsock
  end

  #
  # Access to client cert
  #
  def client_cert
    sslsock.sslctx.cert if sslsock
  end

  #
  # Access to client key
  #
  def client_key
    sslsock.sslctx.key if sslsock
  end

  #
  # Access to the current cipher
  #
  def cipher
    sslsock.cipher if sslsock
  end

  #
  # Prevent a sysread from the bare socket
  #
  def sysread(*args)
    raise RuntimeError, "Invalid sysread() call on SSL socket"
  end

  #
  # Prevent a sysread from the bare socket
  #
  def syswrite(*args)
    raise RuntimeError, "Invalid syswrite() call on SSL socket"
  end

  #
  # This flag determines whether to use the non-blocking openssl
  # API calls when they are available. This is still buggy on
  # Linux/Mac OS X, but is required on Windows
  #
  def allow_nonblock?
    avail = self.sslsock.respond_to?(:accept_nonblock)
    if avail and Rex::Compat.is_windows
      return true
    end
    false
  end

  attr_reader :peer_verified # :nodoc:
  attr_reader :ssl_negotiated_version # :nodoc:
  attr_accessor :sslsock, :sslctx, :sslhash # :nodoc:

  def type?
    return 'tcp-ssl'
  end

protected

  attr_writer :peer_verified # :nodoc:
  attr_writer :ssl_negotiated_version # :nodoc:


rescue LoadError
end

end

