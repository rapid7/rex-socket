# -*- coding:binary -*-
require 'rex/socket/parameters'

RSpec.describe Rex::Socket::Parameters do

  let(:args) { { } }
  subject(:params) { described_class.new(args) }

  it { is_expected.to respond_to(:localhost) }
  it { is_expected.to respond_to(:localport) }
  it { is_expected.to respond_to(:client?) }
  it { is_expected.to respond_to(:server?) }
  it { is_expected.to respond_to(:ssl?) }
  it { is_expected.to respond_to(:v6?) }

  describe '.new' do

    it 'should handle an IPv4 local host definition' do
      params = Rex::Socket::Parameters.new({ 'LocalHost' => '1.2.3.4', 'LocalPort' => 1234 })
      expect(params.localhost).to eq '1.2.3.4'
      expect(params.localport).to eq 1234
      expect(params.v6?).to eq false
    end

    it 'should handle an IPv4 peer host definition' do
      params = Rex::Socket::Parameters.new({ 'PeerHost' => '1.2.3.4', 'PeerPort' => 1234 })
      expect(params.peerhost).to eq '1.2.3.4'
      expect(params.peerport).to eq 1234
      expect(params.v6?).to eq false
    end

    [ nil, true ].each do |ipv6|
      it "should handle an IPv6 local host definition with IPv6 set to #{ipv6.inspect}" do
        params = Rex::Socket::Parameters.new({ 'LocalHost' => '::1', 'LocalPort' => 1234, 'IPv6' => ipv6 })
        expect(params.localhost).to eq '::1'
        expect(params.localport).to eq 1234
        expect(params.v6?).to eq true
      end
    end

    [ nil, true ].each do |ipv6|
      context "given an IPv6 peer host definition with IPv6 set to #{ipv6.inspect}" do
        params = Rex::Socket::Parameters.new({ 'PeerHost' => '::1', 'PeerPort' => 1234, 'IPv6' => ipv6 })
        it 'should set the local host correctly' do
          expect(params.localhost).to eq '::'
          expect(params.localport).to eq 0
        end

        it 'should set the peer host correctly' do
          expect(params.peerhost).to eq '::1'
          expect(params.peerport).to eq 1234
        end

        it 'should set #v6? correctly' do
          expect(params.v6?).to eq true
        end
      end
    end

    context "given no value for IPv6" do
      [
        {'Options' => { 'LocalHost' => '127.0.0.1', 'PeerHost' => '127.0.0.1' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => '127.0.0.1', 'PeerHost' => '::1' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => '127.0.0.1', 'PeerHost' => 'localhost' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => '127.0.0.1', 'PeerHost' => nil }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => '::1', 'PeerHost' => '127.0.0.1' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => '::1', 'PeerHost' => '::1' }, 'ExpectedResult' => true },
        {'Options' => { 'LocalHost' => '::1', 'PeerHost' => 'localhost' }, 'ExpectedResult' => true },
        {'Options' => { 'LocalHost' => '::1', 'PeerHost' => nil }, 'ExpectedResult' => true },
        {'Options' => { 'LocalHost' => 'localhost', 'PeerHost' => '127.0.0.1' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => 'localhost', 'PeerHost' => '::1' }, 'ExpectedResult' => true },
        {'Options' => { 'LocalHost' => 'localhost', 'PeerHost' => 'localhost' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => 'localhost', 'PeerHost' => nil }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => nil, 'PeerHost' => '127.0.0.1' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => nil, 'PeerHost' => '::1' }, 'ExpectedResult' => true },
        {'Options' => { 'LocalHost' => nil, 'PeerHost' => 'localhost' }, 'ExpectedResult' => false },
        {'Options' => { 'LocalHost' => nil, 'PeerHost' => nil }, 'ExpectedResult' => false }
      ].each do |test|
        options = test['Options']
        it "should automatically set v6 to #{test['ExpectedResult']} when localhost is #{options['LocalHost'].inspect} and peerhost is #{options['PeerHost'].inspect}" do
          params = Rex::Socket::Parameters.new(options)
          expect(params.v6).to eq test['ExpectedResult']
        end
      end
    end
  end

  describe '#merge' do
    it "should handle merging" do
      new_params = params.merge(Rex::Socket::Parameters.new({"LocalHost" => "5.6.7.8", "LocalPort" => 5678 }))
      expect(params.localhost).to eq "0.0.0.0"
      expect(params.localport).to eq 0
      expect(new_params.localhost).to eq "5.6.7.8"
      expect(new_params.localport).to eq 5678
    end

    it "should handle merging hash options" do
      expect(params.localhost).to eq "0.0.0.0"
      expect(params.localport).to eq 0
      new_params = params.merge({"LocalHost" => "5.6.7.8", "LocalPort" => 5678 })
      expect(params.localhost).to eq "0.0.0.0"
      expect(params.localport).to eq 0
      expect(new_params.localhost).to eq "5.6.7.8"
      expect(new_params.localport).to eq 5678
    end

    it "should handle new proxy definitions" do
      expect(params.proxies).to eq nil
      new_params = params.merge({"Proxies" => "1.2.3.4:1234, 5.6.7.8:5678"})
      expect(params.proxies).to eq nil
      expect(new_params.proxies).to eq [
        ["1.2.3.4", "1234"],
        ["5.6.7.8", "5678"]
      ]
    end
  end

  describe '#merge!' do
    it "should handle merging in place" do
      expect(params.localhost).to eq "0.0.0.0"
      expect(params.localport).to eq 0
      params.merge!(Rex::Socket::Parameters.new({"LocalHost" => "5.6.7.8", "LocalPort" => 5678 }))
      expect(params.localhost).to eq "5.6.7.8"
      expect(params.localport).to eq 5678
    end
  end

end
