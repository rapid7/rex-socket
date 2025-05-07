# -*- coding:binary -*-
require 'rex/socket/parameters'

RSpec.describe Rex::Socket::Comm::Local do
  describe '.create_by_type' do
    let(:type) { ::Socket::SOCK_STREAM }
    let(:proto) { ::Socket::IPPROTO_TCP }
    let(:params) { Rex::Socket::Parameters.new({ 'PeerHost' => '192.0.2.1', 'PeerPort' => 1234 }) }
    let(:sock) { RSpec::Mocks::Double.new('socket') }

    before(:each) do
      allow(Rex::Socket).to receive(:support_ipv6?).with(no_args).and_return(true)
      allow(::Socket).to receive(:new).with(any_args).and_return(sock)
      allow(sock).to receive(:setsockopt).with(any_args)
      allow(sock).to receive(:bind).with(any_args)
      allow(sock).to receive(:connect).with(any_args).and_return(nil)
    end

    it 'creates an IPv4 socket' do
      expect(::Socket).to receive(:new).with(::Socket::AF_INET, type, proto).and_return(sock)
      described_class.create_by_type(params, type, proto)
    end

    it 'connects the new socket' do
      expect(sock).to receive(:connect).with(Rex::Socket.to_sockaddr(params.peerhost, params.peerport)).and_return(nil)
      described_class.create_by_type(params, type, proto)
    end

    it 'connects directly to the target' do
      expect(described_class).to_not receive(:proxy)
      described_class.create_by_type(params, type, proto)
    end

    context 'with proxies set' do
      let(:params) { Rex::Socket::Parameters.new({ 'PeerHost' => '192.0.2.1', 'PeerPort' => 1234, 'Proxies' => 'http:192.0.2.2:8080, socks5:192.0.2.3:1080' }) }

      it 'does not resolve the hostname' do
        expect(Rex::Socket).to_not receive(:getaddresses)
      end

      it 'connects to the target through a proxy' do
        expect(sock).to receive(:connect).with(Rex::Socket.to_sockaddr('192.0.2.2', 8080)).and_return(nil)

        expect(described_class).to receive(:proxy).with(sock, 'http', '192.0.2.3', 1080).and_return(nil).ordered
        expect(described_class).to receive(:proxy).with(sock, 'socks5', params.peerhost, params.peerport).and_return(nil).ordered
        described_class.create_by_type(params, type, proto)
      end
    end
  end

  describe '.proxy' do
    let(:sock) { RSpec::Mocks::Double.new('socket') }
    let(:host) { '192.0.2.1' }
    let(:port) { 8080 }

    context 'when type is http' do
      let(:type) { 'http' }

      it 'connects via HTTP' do
        data = "CONNECT #{host}:#{port} HTTP/1.0\r\n\r\n"
        expect(sock).to receive(:put).with(data).and_return(data.length)
        expect(sock).to receive(:get_once).and_return("HTTP/1.1 200 Connection Established\r\n\r\n")
        described_class.proxy(sock, type, host, port)
      end
    end

    context 'when type is invalid' do
      let(:type) { 'invalid' }

      it 'raises an error' do
        expect {
          described_class.proxy(sock, type, host, port)
        }.to raise_error(RuntimeError, /proxy type specified is not valid/)
      end
    end

    context 'when type is socks4' do
      let(:type) { 'socks4' }
      let(:host) { 'localhost' }

      it 'resolves the hostname to an address' do
        expect(Rex::Socket).to receive(:getaddress).with(host, false).and_return('127.0.0.1')
        expect(described_class).to receive(:proxy_socks4a).with(sock, type, '127.0.0.1', port)
        described_class.proxy(sock, type, host, port)
      end
    end

    context 'when type is socks5' do
      let(:type) { 'socks5' }
      let(:host) { 'localhost' }

      it 'resolves the hostname to an address' do
        expect(Rex::Socket).to receive(:getaddress).with(host, Rex::Socket.support_ipv6?).and_return('127.0.0.1')
        expect(described_class).to receive(:proxy_socks5h).with(sock, type, '127.0.0.1', port)
        described_class.proxy(sock, type, host, port)
      end
    end

    context 'when type is socks5h' do
      let(:type) { 'socks5h' }
      let(:host) { 'localhost' }

      it 'does not resolve the hostname to an address' do
        expect(Rex::Socket).to_not receive(:getaddress)
        expect(described_class).to receive(:proxy_socks5h).with(sock, type, host, port)
        described_class.proxy(sock, type, host, port)
      end
    end
  end
end