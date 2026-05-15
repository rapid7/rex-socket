# -*- coding: binary -*-
require 'spec_helper'

RSpec.describe Rex::Socket::Udp do
  let(:receiver) { UDPSocket.new.tap { |s| s.bind('127.0.0.1', 0) } }
  let(:recv_port) { receiver.addr[1] }
  let(:socket) { Rex::Socket::Udp.create('LocalHost' => '127.0.0.1') }

  after do
    socket.close rescue nil
    receiver.close rescue nil
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
  end
end
