module R2D2
  class GooglePaymentToken < PaymentToken
    SignatureInvalidError = Class.new(PaymentToken::Error)
    MessageExpiredError = Class.new(PaymentToken::Error)

    HKDF_INFO = 'Google'

    attr_reader :protocol_version, :recipient_id, :verification_keys, :signature, :signed_message

    def self.to_length_value(*chunks)
      chunks.flat_map do |chunk|
        chunk_size = 4.times.map do |index|
          (chunk.bytesize >> (8 * index)) & 0xFF
        end
        chunk_size.pack('C*') + chunk
      end.join
    end

    def initialize(token_attrs, recipient_id:, verification_keys:)
      @protocol_version = token_attrs['protocolVersion']
      raise ArgumentError, "unknown protocolVersion #{protocol_version}" unless protocol_version == 'ECv1'

      @recipient_id = recipient_id
      @verification_keys = verification_keys
      @signature = token_attrs['signature']
      @signed_message = token_attrs['signedMessage']
    end

    def decrypt(private_key_pem)
      verified_message = verify_message

      @ephemeral_public_key = verified_message['ephemeralPublicKey']
      @tag = verified_message['tag']
      @encrypted_message = verified_message['encryptedMessage']
      message = super

      expired = message['messageExpiration'].to_f / 1000.0 <= Time.now.to_f
      raise MessageExpiredError if expired

      message
    end

    private

    def verify_message
      digest = OpenSSL::Digest::SHA256.new
      signed_bytes = self.class.to_length_value(
        'Google',
        recipient_id,
        protocol_version,
        signed_message
      )
      verified = verification_keys['keys'].any? do |key|
        next if key['protocolVersion'] != protocol_version

        ec = OpenSSL::PKey::EC.new(Base64.strict_decode64(key['keyValue']))
        ec.verify(digest, Base64.strict_decode64(signature), signed_bytes)
      end

      if verified
        JSON.parse(signed_message)
      else
        raise SignatureInvalidError
      end
    end
  end
end
