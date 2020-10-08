module R2D2
  Error = Class.new(StandardError)
  TagVerificationError = Class.new(R2D2::Error)
  SignatureInvalidError = Class.new(R2D2::Error)
  MessageExpiredError = Class.new(R2D2::Error)

  def build_token(token_attrs, recipient_id: nil, verification_keys: nil)
    protocol_version = token_attrs.fetch('protocolVersion', 'ECv0')

    case protocol_version
    when 'ECv0'
      AndroidPayToken.new(token_attrs)
    when 'ECv1', 'ECv2'
      raise ArgumentError, "missing keyword: recipient_id" if recipient_id.nil?
      raise ArgumentError, "missing keyword: verification_keys" if verification_keys.nil?

      GooglePayToken.new(token_attrs, recipient_id: recipient_id, verification_keys: verification_keys)
    else
      raise ArgumentError, "unknown protocolVersion #{protocol_version}"
    end
  end
  module_function :build_token

  module Util
    def generate_shared_secret(private_key, ephemeral_public_key)
      ec = OpenSSL::PKey::EC.new('prime256v1')
      bn = OpenSSL::BN.new(Base64.decode64(ephemeral_public_key), 2)
      point = OpenSSL::PKey::EC::Point.new(ec.group, bn)
      private_key.dh_compute_key(point)
    end

    def derive_hkdf_keys(ephemeral_public_key, shared_secret, info, key_length_bytes = 16)
      key_material = Base64.decode64(ephemeral_public_key) + shared_secret
      hkdf_bytes = hkdf(key_material, info, key_length_bytes * 2)
      ## No possibility for out of bounds reads, ruby prevents it when indexing a string past its maximum index.
      {
        symmetric_encryption_key: hkdf_bytes[0..(key_length_bytes - 1)],
        mac_key: hkdf_bytes[key_length_bytes..(key_length_bytes * 2)]
      }
    end

    def verify_mac(mac_key, encrypted_message, tag)
      digest = OpenSSL::Digest.new('sha256')
      mac = OpenSSL::HMAC.digest(digest, mac_key, Base64.decode64(encrypted_message))
      raise TagVerificationError unless secure_compare(mac, Base64.decode64(tag))
    end

    def decrypt_message(encrypted_data, symmetric_key, cipher_key_length_bits = 128)
      raise ArgumentError, "Invalid cipher_key_length #{cipher_key_length_bits} must be 128 or 256" unless [128, 256].include?(cipher_key_length_bits)

      decipher = cipher_key_length_bits == 256 ? OpenSSL::Cipher::AES256.new(:CTR) : OpenSSL::Cipher::AES128.new(:CTR)
      decipher.decrypt
      decipher.key = symmetric_key
      decipher.update(Base64.decode64(encrypted_data)) + decipher.final
    end

    def to_length_value(*chunks)
      value = ''
      chunks.each do |chunk|
        chunk_size = 4.times.map do |index|
          (chunk.bytesize >> (8 * index)) & 0xFF
        end
        value << chunk_size.pack('C*')
        value << chunk
      end
      value
    end

    private

    if defined?(FastSecureCompare)
      def secure_compare(a, b)
        FastSecureCompare.compare(a, b)
      end
    else
      # constant-time comparison algorithm to prevent timing attacks; borrowed from ActiveSupport::MessageVerifier
      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        l = a.unpack("C#{a.bytesize}")

        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res == 0
      end
    end

    if defined?(OpenSSL::KDF) && OpenSSL::KDF.respond_to?(:hkdf)
      def hkdf(key_material, info, length = 32)
        OpenSSL::KDF.hkdf(key_material, salt: 0.chr * 32, info: info, length: length, hash: 'sha256')
      end
    else
      begin
        require 'hkdf'
      rescue LoadError
        STDERR.puts "You need at least Ruby OpenSSL gem 2.1 (installed: #{OpenSSL::VERSION}) " \
        "and system OpenSSL 1.1.0 (installed: #{OpenSSL::OPENSSL_LIBRARY_VERSION}) for HKDF support." \
        "You can add \"gem 'hkdf'\" to your Gemfile for a Ruby-based fallback."
        raise
      end

      def hkdf(key_material, info, length = 32)
        HKDF.new(key_material, algorithm: 'SHA256', info: info).next_bytes(length)
      end
    end
  end
end
