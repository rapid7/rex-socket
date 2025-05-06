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

      it 'connects to the target through a proxy' do
        expect(sock).to receive(:connect).with(Rex::Socket.to_sockaddr('192.0.2.2', 8080)).and_return(nil)

        expect(described_class).to receive(:proxy).with(sock, 'http', '192.0.2.3', 1080).and_return(nil).ordered
        expect(described_class).to receive(:proxy).with(sock, 'socks5', params.peerhost, params.peerport).and_return(nil).ordered
        described_class.create_by_type(params, type, proto)
      end
    end
  end
end