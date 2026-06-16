# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Socket::Udp do
  let(:loopback) { '127.0.0.1' }
  let(:receiver) { UDPSocket.new.tap { |s| s.bind(loopback, 0) } }
  let(:recv_port) { receiver.addr[1] }
  let(:socket) { described_class.create('LocalHost' => loopback) }

  def make_server
    described_class.create('LocalHost' => loopback, 'LocalPort' => 0)
  end

  def make_client(port)
    described_class.create('PeerHost' => loopback, 'PeerPort' => port)
  end

  describe '#recvfrom' do
    it 'returns the data and a stdlib-style sender address tuple' do
      server = make_server
      client = make_client(server.local_address.ip_port)
      client.write('hello')

      data, addr = server.recvfrom(65535)
      expect(data).to eq('hello')
      expect(addr).to be_an(Array)
      expect(addr.length).to eq(4)

      af_name, port, host, numeric = addr
      expect(af_name).to eq('AF_INET')
      expect(port).to be_a(Integer)
      expect(host).to eq(loopback)
      expect(numeric).to eq(loopback)
    ensure
      client&.close
      server&.close
    end
  end

  describe '#send' do
    it 'delivers a datagram with the 4-arg (host, port) form' do
      socket.send('hello', 0, '127.0.0.1', recv_port)
      expect(IO.select([receiver], nil, nil, 1)).not_to be_nil
      expect(receiver.recvfrom(16).first).to eq('hello')
    end

    it 'delivers a datagram with the 3-arg (packed sockaddr) form' do
      sockaddr = Socket.pack_sockaddr_in(recv_port, '127.0.0.1')
      socket.send('world', 0, sockaddr)
      expect(IO.select([receiver], nil, nil, 1)).not_to be_nil
      expect(receiver.recvfrom(16).first).to eq('world')
    end

    # #sendto uses send, so we'll test IO here
    it 'delivers binary data' do
      socket.send("\xE2\x9C\x85".b, 0, '127.0.0.1', recv_port) # unicode checkmark
      expect(IO.select([receiver], nil, nil, 1)).not_to be_nil
      expect(receiver.recvfrom(16).first).to eq("\xE2\x9C\x85".b)
    end

    it 'delivers null bytes' do
      socket.send("\x00\x00\x00\x00".b, 0, '127.0.0.1', recv_port)
      expect(IO.select([receiver], nil, nil, 1)).not_to be_nil
      expect(receiver.recvfrom(16).first).to eq("\x00\x00\x00\x00".b)
    end
  end

  describe '#sendto' do
    it 'emits a deprecation warning' do
      expect { socket.sendto('hi', '127.0.0.1', recv_port) }
        .to output(/sendto.*deprecated/i).to_stderr
    end

    it 'still delivers the datagram' do
      socket.sendto('hi', '127.0.0.1', recv_port)
      expect(IO.select([receiver], nil, nil, 1)).not_to be_nil
      expect(receiver.recvfrom(16).first).to eq('hi')
    end

    it 'calls .send with the expected arguments' do
      expect(socket).to receive(:send).with('data', 0, '127.1.1.1', 1337)
      socket.sendto('data', '127.1.1.1', 1337)
    end
  end

  describe '#timed_recvfrom' do
    it 'returns the datagram and sender address when one arrives in time' do
      server = make_server
      client = make_client(server.local_address.ip_port)
      client.write('ping')

      result = server.timed_recvfrom(65535, 5)
      expect(result).to_not be_nil

      data, addr = result
      expect(data).to eq('ping')
      expect(addr).to eq(['AF_INET', addr[1], loopback, loopback])
    ensure
      client&.close
      server&.close
    end

    it 'returns nil when no datagram arrives before the timeout' do
      server = make_server
      expect(server.timed_recvfrom(65535, 0.1)).to be_nil
    ensure
      server&.close
    end
  end
end
