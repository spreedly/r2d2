$LOAD_PATH.push File.expand_path("../lib", __FILE__)
require 'test/unit'
require 'json'
require 'android_pay'

class Android_Pay::PaymentTokenTest < Test::Unit::TestCase

  def setup
    fixtures = File.dirname(__FILE__) + "/fixtures/"
    @token_attrs = JSON.parse(File.read(fixtures + "token.json"))
    @private_key = File.read(fixtures + "private_key.pem")
    @payment_token = Android_Pay::PaymentToken.new(@token_attrs)
    @shared_secret = ['44a9715c18ebcb255af705f7332657420aca40604334a7d48a89baba18280a97']
  end

  def test_initialize
    assert_equal Base64.decode64(@token_attrs["ephemeralPublicKey"]), @payment_token.ephemeral_public_key
    assert_equal Base64.decode64(@token_attrs["tag"]), @payment_token.tag
    assert_equal Base64.decode64(@token_attrs["data"]), @payment_token.data
  end


  def test_decrypt
    payment_data = JSON.parse(@payment_token.decrypt( @private_key))
    assert_equal "4895370012003478", payment_data["dpan"]
    assert_equal 12, payment_data["expirationMonth"]
    assert_equal 2020, payment_data["expirationYear"]
    assert_equal "3DS", payment_data["authMethod"]
    assert_equal "AgAAAAAABk4DWZ4C28yUQAAAAAA=", payment_data["3dsCryptogram"]
    assert_equal "07", payment_data["3dsEciIndicator"]
  end

  def test_shared_secret
    priv_key = OpenSSL::PKey::EC.new(@private_key)
    assert_equal @shared_secret, Android_Pay::PaymentToken.generate_shared_secret(priv_key, Base64.decode64(@token_attrs["ephemeralPublicKey"])).unpack('H*')
  end

end
