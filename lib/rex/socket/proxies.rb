# -*- coding: binary -*-

module Rex
  module Socket
    module Proxies
      module ProxyType
        SAPNI = 'sapni'
        HTTP = 'http'
        SOCKS4 = 'socks4'
        SOCKS5 = 'socks5'
        SOCKS5H = 'socks5h'
      end

      # @param [String,nil] value A proxy chain of format {type:host:port[,type:host:port][...]}
      # @return [Array<URI>] The array of proxies
      def self.parse(value)
        proxies = []
        value.to_s.strip.split(',').each do |proxy|
          proxy = proxy.strip

          # replace the first : with :// so it can be parsed as a URI
          # URIs will offer more flexibility long term, but we'll keep backwards compatibility for now by treating : as ://
          proxy = proxy.sub(/\A(\w+):(\w+)/, '\1://\2')
          uri = URI(proxy)

          unless supported_types.include?(uri.scheme)
            raise Rex::RuntimeError.new("Unsupported proxy scheme: #{uri.scheme}")
          end

          if uri.host.nil? || uri.host.empty?
            raise Rex::RuntimeError.new("A proxy URI must include a valid host.")
          end

          if uri.port.nil? && uri.scheme.start_with?('socks')
            uri.port = 1080
          end

          if uri.port.nil? || uri.port.zero?
            raise Rex::RuntimeError.new("A proxy URI must include a valid port.")
          end

          proxies << uri
        end

        proxies
      end

      def self.supported_types
        ProxyType.constants.map { |c| ProxyType.const_get(c) }
      end
    end
  end
end
