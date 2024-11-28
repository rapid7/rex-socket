# -*- coding: binary -*-

module Rex
  module Socket
    module Proxies
      module ProxyType
        SAPNI = 'sapni'
        HTTP = 'http'
        SOCKS4 = 'socks4'
        SOCKS5 = 'socks5'
      end

      # @param [String,nil] value A proxy chain of format {type:host:port[,type:host:port][...]}
      # @return [Array] The array of proxies, i.e. {[['type', 'host', 'port']]}
      def self.parse(value)
        value.to_s.strip.split(',').map { |a| a.strip }.map { |a| a.split(':').map { |b| b.strip } }
      end

      def self.supported_types
        ProxyType.constants.map { |c| ProxyType.const_get(c) }
      end
    end
  end
end
