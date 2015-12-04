$LOAD_PATH.push File.expand_path("../lib", __FILE__)
require 'test/unit'
require 'json'
require 'r2d2'

class R2D2::PaymentTokenTest < Test::Unit::TestCase

  def setup
    fixtures = File.dirname(__FILE__) + "/fixtures/"
    @token_attrs = JSON.parse(File.read(fixtures + "token.json"))
    @private_key = File.read(fixtures + "private_key.pem")
    @payment_token = R2D2::PaymentToken.new(@token_attrs)
    @shared_secret = ['44a9715c18ebcb255af705f7332657420aca40604334a7d48a89baba18280a97']
    @mac_key = ["d"]
    @symmetric_encryption_key = ["c7b2670dc0630edd0a9101dd5d70e4b2"]
  end

  def test_initialize
    assert_equal Base64.decode64(@token_attrs["ephemeralPublicKey"]), @payment_token.ephemeral_public_key
    assert_equal Base64.decode64(@token_attrs["tag"]), @payment_token.tag
    assert_equal Base64.decode64(@token_attrs["data"]), @payment_token.data
  end

  def test_successful_decrypt
    payment_data = JSON.parse(@payment_token.decrypt( @private_key))
    assert_equal "4895370012003478", payment_data["dpan"]
    assert_equal 12, payment_data["expirationMonth"]
    assert_equal 2020, payment_data["expirationYear"]
    assert_equal "3DS", payment_data["authMethod"]
    assert_equal "AgAAAAAABk4DWZ4C28yUQAAAAAA=", payment_data["cryptogram"]
    assert_equal "07", payment_data["eciIndicator"]
  end

  def test_shared_secret
    priv_key = OpenSSL::PKey::EC.new(@private_key)
    assert_equal @shared_secret, R2D2::PaymentToken.generate_shared_secret(priv_key, @payment_token.ephemeral_public_key).unpack('H*')
  end

  def test_derive_hkdf_keys
    hkdf_keys = R2D2::PaymentToken.derive_hkdf_keys(@payment_token.ephemeral_public_key, @shared_secret[0])
    assert_equal hkdf_keys[:symmetric_encryption_key].unpack('H*'), @symmetric_encryption_key
    assert_equal hkdf_keys[:mac_key].unpack('*H'), @mac_key
  end

  def test_invalid_tag
    @payment_token.tag = "SomethingBogus"
    assert_raise R2D2::PaymentToken::TagVerificationError do
      JSON.parse(@payment_token.decrypt( @private_key))
    end
  end

end
