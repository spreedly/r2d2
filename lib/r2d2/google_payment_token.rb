module R2D2
  class GooglePaymentToken < PaymentToken
    SignatureInvalidError = Class.new(PaymentToken::Error)

    attr_reader :protocol_version, :merchant_id, :verification_keys, :signature, :signed_message

    def initialize(token_attrs, merchant_id:, verification_keys:)
      @protocol_version = token_attrs['protocolVersion']
      raise ArgumentError, "unknown protocolVersion #{protocol_version}" unless protocol_version == 'ECv1'

      @merchant_id = merchant_id
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

      payment_method = message['paymentMethod']
      raise ArgumentError, "unknown paymentMethod #{payment_method}" unless payment_method == 'TOKENIZED_CARD'
      message['paymentMethodDetails']
    end

    private

    def verify_message
      digest = OpenSSL::Digest::SHA256.new
      signed_bytes = self.class.to_length_value(
        'Google',
        "merchant:#{merchant_id}",
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

    class << self
      def derive_hkdf_keys(ephemeral_public_key, shared_secret, info = 'Google')
        super
      end

      def to_length_value(*chunks)
        chunks.flat_map do |chunk|
          chunk_size = 4.times.map do |index|
            (chunk.bytesize >> (8 * index)) & 0xFF
          end
          bytes = chunk_size + chunk.unpack('C*')
          bytes.pack('C*')
        end.join
      end
    end
  end
end
