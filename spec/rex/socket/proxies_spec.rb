# -*- coding:binary -*-
require 'uri'
require 'rex/socket/proxies'

RSpec.describe Rex::Socket::Proxies do
  describe '.supported_types' do
    it 'should equal the array of available proxies' do
      expected = %w[
        sapni
        socks4
        http
        socks5
        socks5h
      ]
      expect(subject.supported_types).to match_array expected
    end
  end

  describe '.parse' do
    [
      { value: nil, expected: [] },
      { value: '', expected: [] },
      { value: '           ', expected: [] },
      { value: 'http://localhost', expected: [URI('http://localhost:80')]},
      { value: 'http:localhost:8080', expected: [URI('http://localhost:8080')]},
      { value: 'socks4://localhost', expected: [URI('socks4://localhost:1080')] },
      { value: 'socks5://localhost', expected: [URI('socks5://localhost:1080')] },
      { value: 'socks5h://localhost', expected: [URI('socks5h://localhost:1080')] },
      { value: 'sapni:198.51.100.1:8080,       socks4:198.51.100.1:1080      ', expected: [URI('sapni://198.51.100.1:8080'), URI('socks4://198.51.100.1:1080')] },
    ].each do |test|
      it "correctly parses #{test[:value]} as #{test[:expected]}" do
        expect(described_class.parse(test[:value])).to eq test[:expected]
      end
    end
  end
end
