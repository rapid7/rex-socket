# -*- coding: binary -*-
require 'rex/socket'
require 'rex/io/stream'

class ::Socket
  IPPROTO_SCTP = 132
  SOL_SCTP     = 132
end

###
#
# This class provides methods for interacting with a SCTP client connection.
#
###
module Rex::Socket::Sctp

  include Rex::Socket
  include Rex::IO::Stream

  ##
  #
  # Factory
  #
  ##

  #
  # Creates the client using the supplied hash.
  #
  # @see create_param
  # @see Rex::Socket::Parameters.from_hash
  def self.create(hash = {})
    hash['Proto'] = 'sctp'
    self.create_param(Rex::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base socket class' creation method that automatically
  # sets the parameter's protocol to SCTP.
  #
  def self.create_param(param)
    param.proto = 'sctp'
    Rex::Socket.create_param(param)
  end

  ##
  #
  # Stream mixin implementations
  #
  ##

  #
  # Calls shutdown on the SCTP connection.
  #
  def shutdown(how = ::Socket::SHUT_RDWR)
    begin
      return (super(how) == 0)
    rescue ::Exception
    end
  end

  # returns socket type
  def type?
    return 'sctp'
  end

end
