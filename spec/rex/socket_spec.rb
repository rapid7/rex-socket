# -*- coding:binary -*-
require 'rex/socket/range_walker'
require 'spec_helper'

RSpec.describe Rex::Socket do

  describe '.tcp_socket_pair' do
    let(:mock_thread_factory) do
      double :mock_thread_factory
    end

    before(:each) do
      stub_const('Rex::ThreadFactory', mock_thread_factory)
      # Fallback implementation from https://github.com/rapid7/metasploit-framework/blob/30e66c43a4932df922d7f1d986fb98387bd0ab1a/lib/rex/thread_factory.rb#L27-L37
      allow(mock_thread_factory).to receive(:spawn) do |name, crit, *args, &block|
        if block
          t = ::Thread.new(*args){ |*args_copy| block.call(*args_copy) }
        else
          t = ::Thread.new(*args)
        end
        t[:tm_name] = name
        t[:tm_crit] = crit
        t[:tm_time] = ::Time.now
        t[:tm_call] = caller
        t
      end
    end

    it 'creates two socket pairs' do
      lsock, rsock = described_class.tcp_socket_pair
      lsock.extend(Rex::IO::Stream)
      rsock.extend(Rex::IO::Stream)

      expect(lsock.closed?).to be(false)
      expect(rsock.closed?).to be(false)

      lsock.close
      rsock.close

      expect(lsock.closed?).to be(true)
      expect(rsock.closed?).to be(true)
    end
  end

  describe '.addr_itoa' do

    context 'with explicit v6' do
      it "should convert a number to a human-readable IPv6 address" do
        expect(described_class.addr_itoa(1, true)).to eq "::1"
      end
    end

    context 'with explicit v4' do
      it "should convert a number to a human-readable IPv4 address" do
        expect(described_class.addr_itoa(1, false)).to eq "0.0.0.1"
      end
    end

    context 'without explicit version' do
      it "should convert a number within the range of possible v4 addresses to a human-readable IPv4 address" do
        expect(described_class.addr_itoa(0)).to eq "0.0.0.0"
        expect(described_class.addr_itoa(1)).to eq "0.0.0.1"
        expect(described_class.addr_itoa(0xffff_ffff)).to eq "255.255.255.255"
      end
      it "should convert a number larger than possible v4 addresses to a human-readable IPv6 address" do
        expect(described_class.addr_itoa(0xfe80_0000_0000_0000_0000_0000_0000_0001)).to eq "fe80::1"
        expect(described_class.addr_itoa(0x1_0000_0001)).to eq "::1:0:1"
      end
    end

  end

  describe '.addr_aton' do
    subject(:nbo) do
      described_class.addr_aton(try)
    end

    context 'with ipv6' do
      let(:try) { "fe80::1" }
      it { is_expected.to be_an(String) }
      it { expect(subject.bytes.count).to eq(16) }
      it "should be in the right order" do
        expect(nbo).to eq "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
      end
    end

    context 'with ipv4' do
      let(:try) { "127.0.0.1" }
      it { is_expected.to be_an(String) }
      it { expect(subject.bytes.count).to eq(4) }
      it "should be in the right order" do
        expect(nbo).to eq "\x7f\x00\x00\x01"
      end
    end

    context 'with a hostname' do
      let(:try) { "localhost" }
      it "should resolve" do
        expect(nbo).to be_a(String)
        expect(nbo.encoding).to eq Encoding.find('binary')
        expect([ 4, 16 ]).to include(nbo.length)
      end
    end

  end

  describe '.compress_address' do

    subject(:compressed) do
      described_class.compress_address(try)
    end

    context 'with lots of single 0s' do
      let(:try) { "fe80:0:0:0:0:0:0:1" }
      it { is_expected.to eq "fe80::1" }
    end

  end

  describe '.getaddress' do

    subject { described_class.getaddress('whatever') }

    before(:example) do
      allow(Addrinfo).to receive(:getaddrinfo).and_return(response_addresses.map {|address| Addrinfo.ip(address)})
    end

    context 'when ::Addrinfo.getaddrinfo returns IPv4 responses' do
      let(:response_afamily) { Socket::AF_INET }
      let(:response_addresses) { ["1.1.1.1", "2.2.2.2"] }

      it { is_expected.to be_a(String) }
      it "should return the first ASCII address" do
        expect(subject).to eq "1.1.1.1"
      end
    end

    context 'when ::Addrinfo.getaddrinfo returns IPv6 responses' do
      let(:response_afamily) { Socket::AF_INET6 }
      let(:response_addresses) { ["fe80::1", "fe80::2"] }

      it { is_expected.to be_a(String) }
      it "should return the first ASCII address" do
        expect(subject).to eq "fe80::1"
      end
    end
  end

  describe '.getaddresses' do

    let(:hostname) { 'whatever' }
    let(:accepts_ipv6) { true }
    subject { described_class.getaddresses(hostname, accepts_ipv6) }

    before(:example) do
      allow(Addrinfo).to receive(:getaddrinfo).and_return(response_addresses.map {|address| Addrinfo.ip(address)})
    end

    context 'when ::Addrinfo.getaddrinfo returns IPv4 responses' do
      let(:response_afamily) { Socket::AF_INET }
      let(:response_addresses) { ["1.1.1.1", "2.2.2.2"] }

      it { is_expected.to be_an(Array) }
      it { expect(subject.size).to eq(2) }
      it "should return the ASCII addresses" do
        expect(subject).to include("1.1.1.1")
        expect(subject).to include("2.2.2.2")
      end
    end

    context 'when ::Addrinfo.getaddrinfo returns IPv6 responses' do
      context "when accepts_ipv6 is true" do
        let(:accepts_ipv6) { true }
        let(:response_afamily) { Socket::AF_INET6 }
        let(:response_addresses) { ["fe80::1", "fe80::2"] }

        it { is_expected.to be_an(Array) }
        it { expect(subject.size).to eq(2) }
        it "should return the ASCII addresses" do
          expect(subject).to include("fe80::1")
          expect(subject).to include("fe80::2")
        end
      end

      context "when accepts_ipv6 is false" do
        let(:accepts_ipv6) { false }
        let(:response_afamily) { Socket::AF_INET6 }
        let(:response_addresses) { ["fe80::1", "fe80::2"] }

        it { is_expected.to be_an(Array) }
        it { expect(subject).to be_empty }
      end
    end

    context 'when passed in nil hostname' do
      let(:hostname) { nil }
      let(:response_addresses) { [] }

      it { expect { subject }.to raise_exception(::SocketError, 'getaddrinfo: nodename nor servname provided, or not known') }
    end

    context 'when passed in a numeric hostname' do
      let(:mock_resolver) { double('Resolver', send: nil) }

      before(:each) do
        described_class._install_global_resolver(mock_resolver)
        expect(mock_resolver).not_to receive(:send)
      end

      after(:each) do
        described_class._install_global_resolver(nil)
      end

      context 'when passed in a decimal hostname' do
        let(:hostname) { '0' }
        let(:response_addresses) { ['0.0.0.0'] }

        it { is_expected.to be_an(Array) }
        it { expect(subject.size).to eq(1) }
        it "should return the ASCII addresses" do
          expect(subject).to include("0.0.0.0")
        end
      end

      context 'when passed in a decimal hostname' do
        let(:hostname) { '0x0' }
        let(:response_addresses) { ['0.0.0.0'] }

        it { is_expected.to be_an(Array) }
        it { expect(subject.size).to eq(1) }
        it "should return the ASCII addresses" do
          expect(subject).to include("0.0.0.0")
        end
      end
    end
  end

  describe '.portspec_to_portlist' do

    subject(:portlist) { described_class.portspec_to_portlist portspec_string}
    let(:portspec_string) { '-1,0-10,!2-5,!7,65530-,65536' }

    it 'does not include negative numbers' do
      expect(portlist).to_not include '-1'
    end

    it 'does not include 0' do
      expect(portlist).to_not include '0'
    end

    it 'does not include negated numbers' do
      ['2', '3', '4', '5', '7'].each do |port|
        expect(portlist).to_not include port
      end
    end

    it 'does not include any numbers above 65535' do
      expect(portlist).to_not include '65536'
    end

    it 'expands open ended ranges' do
      (65530..65535).each do |port|
        expect(portlist).to include port
      end
    end
  end

  describe '.is_ipv4?' do
    subject(:addr) do
      described_class.is_ipv4?(try)
    end

    context 'with an IPv4 address' do
      let(:try) { '0.0.0.0' }
      it 'should return true' do
        expect(addr).to eq true
      end
    end

    context 'with multiple IPv4 addresses' do
      context 'separated by newlines' do
        let(:try) { "127.0.0.1\n127.0.0.1" }
        it 'should return false' do
          expect(addr).to eq false
        end
      end

      context 'separated by spaces' do
        let(:try) { "127.0.0.1 127.0.0.1" }
        it 'should return false' do
          expect(addr).to eq false
        end
      end
    end

    context 'with an IPv6 address' do
      let(:try) { '::1' }
      it 'should return false' do
        expect(addr).to eq false
      end
    end

   context 'with a hostname' do
      let(:try) { "localhost" }
      it "should return false" do
        expect(addr).to eq false
      end
   end

    context 'with nil' do
      let(:try) { nil }
      it "should return false" do
        expect(addr).to eq false
      end
    end
  end

  describe '.is_ipv6?' do
    subject(:addr) do
      described_class.is_ipv6?(try)
    end

    context 'with an IPv4 address' do
      let(:try) { '0.0.0.0' }
      it 'should return false' do
        expect(addr).to eq false
      end
    end

    context 'with an IPv6 address' do
      let(:try) { '::' }
      it 'should return true' do
        expect(addr).to eq true
      end
    end

    context 'with multiple IPv6 addresses' do
      context 'separated by newlines' do
        let(:try) { "::1\n::1" }
        it 'should return false' do
          expect(addr).to eq false
        end
      end

      context 'separated by spaces' do
        let(:try) { "::1 ::1" }
        it 'should return false' do
          expect(addr).to eq false
        end
      end
    end

    context 'with a hostname' do
      let(:try) { "localhost" }
      it "should return false" do
        expect(addr).to eq false
      end
    end

    context 'with nil' do
      let(:try) { nil }
      it "should return false" do
        expect(addr).to eq false
      end
    end
  end

  describe '.is_name?' do
     subject(:name) do
      described_class.is_name?(try)
     end

     context 'with a hostname' do
       let(:try) { "localhost" }
       it "should return true" do
         expect(name).to eq true
       end
     end

    context 'with a name containing underscores' do
      let(:try) { '_ldap._tcp.msflab.local' }
      it 'should return true' do
        expect(name).to eq true
      end
    end

    context 'with a fully qualified domain name' do
      context 'and a trailing dot' do
        let(:try) { "www.metasploit.com." }
        it "should return true" do
          expect(name).to eq true
        end
      end

      context 'and no trailing dot' do
        let(:try) { "www.metasploit.com" }
        it "should return true" do
          expect(name).to eq true
        end
      end
    end

    context 'with multiple fully qualified domain names' do
      context 'separated by newlines' do
        let(:try) { "www.metasploit.com\nmetasploit.com" }
        it 'should return false' do
          expect(name).to eq false
        end
      end

      context 'separated by spaces' do
        let(:try) { "www.metasploit.com metasploit.com" }
        it 'should return false' do
          expect(name).to eq false
        end
      end
    end

     context 'international domain names' do
       # 搾取の translation: of exploitation (metasploit)
       let(:try) { "xn--u9jw97h8hl.com" }
       it 'should return true' do
         expect(name).to eq true
       end
     end
  end

  describe '.rex_getaddrinfo' do
    subject(:addrinfos) do
      described_class.rex_getaddrinfo(hostname)
    end

    context 'with a hostname' do
      let(:hostname) { 'localhost' }
      it 'should call .rex_resolve_hostname' do
        expect(described_class).to receive(:rex_resolve_hostname).with(hostname, {resolver: nil}).and_return([ [], [] ])
        subject
      end

      it 'should return IPv4 and IPv6 addresses' do
        expect(described_class).to receive(:rex_resolve_hostname).and_return([
          [Dnsruby::RR::IN::A.new(address: '127.0.0.1')],
          [Dnsruby::RR::IN::AAAA.new(address: '::1')]
        ])

        expect(subject).to match_array([
          have_attributes(ip_address: '127.0.0.1', afamily: ::Socket::AF_INET, socktype: ::Socket::SOCK_STREAM, protocol: ::Socket::IPPROTO_TCP),
          have_attributes(ip_address: '::1', afamily: ::Socket::AF_INET6, socktype: ::Socket::SOCK_STREAM, protocol: ::Socket::IPPROTO_TCP)
        ])
      end
    end

    context 'with an IPv4 name' do
      let(:hostname) { '127.0.0.1' }
      it 'should not call .rex_resolve_hostname' do
        expect(described_class).to_not receive(:rex_resolve_hostname)
        subject
      end

      it 'should return one IPv4 address' do
        expect(subject).to match_array([
          have_attributes(ip_address: '127.0.0.1', afamily: ::Socket::AF_INET, socktype: ::Socket::SOCK_STREAM, protocol: ::Socket::IPPROTO_TCP),
        ])
      end
    end

    context 'with an IPv6 name' do
      let(:hostname) { '::1' }
      it 'should not call .rex_resolve_hostname' do
        expect(described_class).to_not receive(:rex_resolve_hostname)
        subject
      end

      it 'should return one IPv6 address' do
        expect(subject).to match_array([
          have_attributes(ip_address: '::1', afamily: ::Socket::AF_INET6, socktype: ::Socket::SOCK_STREAM, protocol: ::Socket::IPPROTO_TCP),
        ])
      end
    end

    context 'with a decimal name' do
      let(:hostname) { '255' }
      it 'should not call .rex_resolve_hostname' do
        expect(described_class).to_not receive(:rex_resolve_hostname)
        subject
      end

      it 'should return one IPv4 address' do
        expect(subject).to match_array([
          have_attributes(ip_address: '0.0.0.255', afamily: ::Socket::AF_INET, socktype: ::Socket::SOCK_STREAM, protocol: ::Socket::IPPROTO_TCP),
        ])
      end
    end

    context 'with an invalid decimal name' do
      let(:hostname) { '4294967296' }
      it 'should call .rex_resolve_hostname' do
        expect(described_class).to receive(:rex_resolve_hostname).with(hostname, {resolver: nil}).and_raise(::SocketError.new('getaddrinfo: Name or service not known'))
        expect { subject }.to raise_error(::SocketError)
      end
    end

    context 'with a hexadecimal name' do
      let(:hostname) { '0xff' }
      it 'should not call .rex_resolve_hostname' do
        expect(described_class).to_not receive(:rex_resolve_hostname)
        subject
      end

      it 'should return one IPv4 address' do
        expect(subject).to match_array([
          have_attributes(ip_address: '0.0.0.255', afamily: ::Socket::AF_INET, socktype: ::Socket::SOCK_STREAM, protocol: ::Socket::IPPROTO_TCP),
        ])
      end
    end

    context 'with an invalid hexadecimal name' do
      let(:hostname) { '0x100000000' }
      it 'should call .rex_resolve_hostname' do
        expect(described_class).to receive(:rex_resolve_hostname).with(hostname, {resolver: nil}).and_raise(::SocketError.new('getaddrinfo: Name or service not known'))
        expect { subject }.to raise_error(::SocketError)
      end
    end
  end
end
