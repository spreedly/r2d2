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
  end

  def test_initialize
    assert_equal @token_attrs["ephemeralPublicKey"], @payment_token.ephemeral_public_key
    assert_equal @token_attrs["tag"], @payment_token.tag
    assert_equal @token_attrs["data"], @payment_token.data
    test_decrypt
  end


  def test_decrypt
    # payment_data = @payment_token.decrypt(@token_attrs["ephemeralPublicKey"], @private_key)
    # assert_equal "plaintext", payment_data
    payment_data = JSON.parse(@payment_token.decrypt(@token_attrs["ephemeralPublicKey"], @private_key))
    puts payment_data
    # assert_equal "4109370251004320", payment_data["applicationPrimaryAccountNumber"]
    # assert_equal "200731", payment_data["applicationExpirationDate"]
    # assert_equal "840", payment_data["currencyCode"]
    # assert_equal 100, payment_data["transactionAmount"]
    # assert_equal nil, payment_data["cardholderName"]
    # assert_equal "040010030273", payment_data["deviceManufacturerIdentifier"]
    # assert_equal "3DSecure", payment_data["paymentDataType"]
    # assert_equal "Af9x/QwAA/DjmU65oyc1MAABAAA=", payment_data["paymentData"]["onlinePaymentCryptogram"]
    # assert_equal "5", payment_data["paymentData"]["eciIndicator"]
  end


  # def test_merchant_id
  #   cert = OpenSSL::X509::Certificate.new(@certificate)
  #   assert_equal @merchant_id, Android_Pay::PaymentToken.extract_merchant_id(cert)
  # end

  # def test_shared_secret
  #   priv_key = OpenSSL::PKey::EC.new(@private_key)
  #   assert_equal @shared_secret, Android_Pay::PaymentToken.generate_shared_secret(priv_key, @token_attrs["header"]["ephemeralPublicKey"])
  # end

  # def test_symmetric_key
  #   assert_equal @symmetric_key, Android_Pay::PaymentToken.generate_symmetric_key(@merchant_id, @shared_secret)
  # end
end
