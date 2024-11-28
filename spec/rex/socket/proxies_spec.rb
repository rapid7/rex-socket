# -*- coding:binary -*-
require 'rex/socket/proxies'

RSpec.describe Rex::Socket::Proxies do
  describe '.supported_types' do
    it 'should equal the array of available proxies' do
      expected = %w[
        sapni
        socks4
        http
        socks5
      ]
      expect(subject.supported_types).to match_array expected
    end
  end

  describe '.parse' do
    [
      { value: nil, expected: [] },
      { value: '', expected: [] },
      { value: '           ', expected: [] },
      { value: 'sapni:198.51.100.1:8080,       socks4:198.51.100.1:1080      ', expected: [['sapni', '198.51.100.1', '8080'], ['socks4', '198.51.100.1', '1080']] },
    ].each do |test|
      it "correctly parses #{test[:value]} as #{test[:expected]}" do
        expect(described_class.parse(test[:value])).to eq test[:expected]
      end
    end
  end
end
