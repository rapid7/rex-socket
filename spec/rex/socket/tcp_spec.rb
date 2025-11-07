# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Socket::Tcp do
  describe '#starttls' do
    it 'calls Parameters.to_hash with a hash argument' do
      socket = described_class.create
      expect(Rex::Socket::Parameters).to receive(:from_hash).with({'SSL' => true}).and_return(Rex::Socket::Parameters.new)
      expect(socket).to receive(:initsock_with_ssl_version).and_return(nil)
      socket.starttls('SSL' => true)
    end

    it 'accepts Parameters as an argument' do
      socket = described_class.create
      parameters = Rex::Socket::Parameters.new
      expect(Rex::Socket::Parameters).to_not receive(:new)
      expect(socket).to receive(:initsock_with_ssl_version).with(parameters, Rex::Socket::Ssl::DEFAULT_SSL_VERSION).and_return(nil)
      socket.starttls(parameters)
    end
  end
end