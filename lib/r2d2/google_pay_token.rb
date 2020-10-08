module R2D2
  class GooglePayToken
    include Util

    attr_reader :protocol_version, :recipient_id, :raw_verification_keys, :signature, :signed_message, :intermediate_signing_key

    def initialize(token_attrs, recipient_id:, verification_keys:)
      @protocol_version = token_attrs['protocolVersion']
      @recipient_id = recipient_id
      @raw_verification_keys = verification_keys
      @signature = token_attrs['signature']
      @signed_message = token_attrs['signedMessage']

      # ECv2 only
      @intermediate_signing_key = token_attrs['intermediateSigningKey'] || '{}'
    end

    def decrypt(private_key_pem)
      verified = verify_and_parse_message

      private_key = OpenSSL::PKey::EC.new(private_key_pem)
      shared_secret = generate_shared_secret(private_key, verified['ephemeralPublicKey'])

      hkdf_keys_length_bytes = protocol_version == 'ECv2' ? 32 : 16
      hkdf_keys = derive_hkdf_keys(verified['ephemeralPublicKey'], shared_secret, 'Google', hkdf_keys_length_bytes)
      verify_mac(hkdf_keys[:mac_key], verified['encryptedMessage'], verified['tag'])

      cipher_key_length_bits = protocol_version == 'ECv2' ? 256 : 128
      decrypted = JSON.parse(
        decrypt_message(verified['encryptedMessage'], hkdf_keys[:symmetric_encryption_key], cipher_key_length_bits)
      )

      cur_millis = (Time.now.to_f * 1000).floor
      expired = decrypted['messageExpiration'].to_i <= cur_millis

      raise MessageExpiredError if expired

      decrypted
    end

    private

    def verify_and_parse_message
      case protocol_version
      when 'ECv1'
        verify_and_parse_message_ecv1
      when 'ECv2'
        verify_and_parse_message_ecv2
      else
        raise ArgumentError, "unknown protocolVersion #{protocol_version}"
      end
    end

    def verify_and_parse_message_ecv1
      signed_bytes = to_length_value(
        'Google',
        recipient_id,
        protocol_version,
        signed_message
      )

      verified = valid_key_signatures?(
        verification_keys,
        [signature],
        signed_bytes
      )

      raise SignatureInvalidError unless verified
      JSON.parse(signed_message)
    end

    def verify_and_parse_message_ecv2
      raise SignatureInvalidError, 'intermediate certificate is expired' if intermediate_key_expired?
      raise SignatureInvalidError, 'no valid signature of intermediate key' unless intermediate_key_signature_verified?
      raise SignatureInvalidError, 'signature of signedMessage does not match' unless payload_signature_verified?

      JSON.parse(signed_message)
    end

    ### ECv2 Methods ###
    def intermediate_key_signature_verified?
      intermediate_signatures = intermediate_signing_key['signatures']
      signed_bytes = [sender_id, protocol_version, intermediate_signing_key['signedKey']].map do |str|
        [str.length].pack('V') + str
      end.join

      # Check that at least one of the root keys signed the intermediate
      valid_key_signatures?(
        verification_keys,
        intermediate_signatures,
        signed_bytes
      )
    end

    def payload_signature_verified?
      signed_string_message = [sender_id, ecv2_recipient_id, protocol_version, signed_message].map do |str|
        [str.length].pack('V') + str
      end.join

      # Check that the intermediate key signed the message
      pkey = OpenSSL::PKey::EC.new(Base64.strict_decode64(intermediate_signing_key_signed_key['keyValue']))
      valid_key_signatures?(
        [pkey],
        [signature],
        signed_string_message
      )
    end

    def valid_key_signatures?(signing_keys, signatures, signed)
      signing_keys.product(signatures).any? do |key, sig|
        key.verify(OpenSSL::Digest::SHA256.new, Base64.strict_decode64(sig), signed)
      end
    end

    def verification_keys
      @verification_keys ||= begin
        root_signing_keys = raw_verification_keys['keys'].select do |key|
          key['protocolVersion'] == protocol_version
        end

        root_signing_keys.map! do |key|
          OpenSSL::PKey::EC.new(Base64.strict_decode64(key['keyValue']))
        end
      end
    end

    def intermediate_key_expired?
      cur_millis = (Time.now.to_f * 1000).floor
      intermediate_signing_key_signed_key['keyExpiration'].to_i <= cur_millis
    end

    def intermediate_signing_key_signed_key
      @intermediate_signing_key_signed_key ||= JSON.parse(intermediate_signing_key['signedKey'])
    end

    def ecv2_recipient_id
      "merchant:#{recipient_id}"
    end

    def sender_id
      'Google'
    end
  end
end
