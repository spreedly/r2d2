require "test_helper"

module R2D2
  class UtilTest < Minitest::Test
    include Util

    def setup
      fixtures = __dir__ + "/fixtures/"
      @token_attrs = JSON.parse(File.read(fixtures + "token.json"))
      @private_key = File.read(fixtures + "private_key.pem")
      @payment_token = R2D2::PaymentToken.new(@token_attrs)
      @shared_secret = ['44a9715c18ebcb255af705f7332657420aca40604334a7d48a89baba18280a97']
    end

    def test_shared_secret
      priv_key = OpenSSL::PKey::EC.new(@private_key)
      assert_equal @shared_secret, generate_shared_secret(priv_key, @payment_token.ephemeral_public_key).unpack('H*')
    end

    def test_derive_hkdf_keys
      hkdf_keys = derive_hkdf_keys(@payment_token.ephemeral_public_key, @shared_secret[0])
      assert_equal ["c7b2670dc0630edd0a9101dd5d70e4b2"], hkdf_keys[:symmetric_encryption_key].unpack('H*')
      assert_equal ["d8976b95c980760d8ce3933994c6eda1"], hkdf_keys[:mac_key].unpack('H*')
    end
  end
end
