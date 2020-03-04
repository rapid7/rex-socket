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

    it "should handle an IPv4 local host definition" do
      params = Rex::Socket::Parameters.new({ "LocalHost" => "1.2.3.4", "LocalPort" => 1234 })
      expect(params.localhost).to eq ("1.2.3.4")
      expect(params.localport).to eq 1234
      expect(params.v6?).to eq false
    end

    it "should handle an IPv6 local host definition" do
      params = Rex::Socket::Parameters.new({ "LocalHost" => "::1", "LocalPort" => 1234, "IPv6" => true })
      expect(params.localhost).to eq ("::1")
      expect(params.localport).to eq 1234
      expect(params.v6?).to eq true
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