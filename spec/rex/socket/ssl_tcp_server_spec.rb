# -*- coding: binary -*-
require 'spec_helper'
require 'openssl'

RSpec.describe Rex::Socket::SslTcpServer do
  let(:loopback) { '127.0.0.1' }

  def make_ssl_context
    key  = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new.tap do |c|
      c.version   = 2
      c.serial    = 1
      c.subject   = OpenSSL::X509::Name.parse('/CN=test')
      c.issuer    = c.subject
      c.public_key = key.public_key
      c.not_before = Time.now - 1
      c.not_after  = Time.now + 3600
      c.sign(key, OpenSSL::Digest::SHA256.new)
    end
    ctx           = OpenSSL::SSL::SSLContext.new
    ctx.key       = key
    ctx.cert      = cert
    ctx
  end

  def make_server(ctx = make_ssl_context)
    described_class.create(
      'LocalHost' => loopback,
      'LocalPort' => 0,
      'SSLContext' => ctx
    )
  end

  def make_client(port, ctx = nil)
    raw = TCPSocket.new(loopback, port)
    client_ctx = OpenSSL::SSL::SSLContext.new
    client_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    ssl = OpenSSL::SSL::SSLSocket.new(raw, client_ctx)
    ssl.connect
    ssl
  rescue => e
    raw&.close
    raise e
  end

  describe '#accept' do
    it 'completes the TLS handshake and returns an SSL-wrapped socket' do
      server = make_server
      port   = server.local_address.ip_port

      client_thread = Thread.new { make_client(port) }

      accepted = server.accept
      client   = client_thread.value

      expect(accepted).not_to be_nil
      expect(accepted).to respond_to(:sslsock)

      client.write('hello')
      expect(accepted.get_once).to eq('hello')
    ensure
      accepted&.close rescue nil
      client&.close   rescue nil
      server&.close   rescue nil
    end

    it 'accepts multiple sequential connections without raising NoMethodError' do
      server = make_server
      port   = server.local_address.ip_port

      3.times do
        client_thread = Thread.new { make_client(port) }
        accepted = server.accept
        client   = client_thread.value

        expect(accepted).not_to be_nil
        client.close   rescue nil
        accepted.close rescue nil
      end
    ensure
      server&.close rescue nil
    end

    it 'does not raise NoMethodError for sslsock during non-blocking TLS accept' do
      # Regression test for the bug where accept_nonblock retry paths called
      # self.sslsock (the server, which has no such method) instead of the
      # ssl local variable (the SSLSocket being accepted).
      server = make_server
      port   = server.local_address.ip_port

      client_thread = Thread.new { make_client(port) }

      accepted = server.accept
      expect(accepted).not_to be_nil

      client = client_thread.value
    ensure
      accepted&.close rescue nil
      client&.close   rescue nil
      server&.close   rescue nil
    end

    it 'returns nil and does not raise when a client connects but aborts the TLS handshake' do
      server = make_server
      port   = server.local_address.ip_port

      # Connect a raw TCP socket without doing TLS — the handshake will fail
      client_thread = Thread.new do
        raw = TCPSocket.new(loopback, port)
        raw.close
      end

      result = server.accept
      expect(result).to be_nil

      client_thread.join
    ensure
      server&.close rescue nil
    end
  end
end
