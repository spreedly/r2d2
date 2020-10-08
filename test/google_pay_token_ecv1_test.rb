require "test_helper"

module R2D2
  class GooglePayTokenTest < Minitest::Test
    def setup
      @recipient_id = 'merchant:12345678901234567890'
      @fixtures = __dir__ + "/fixtures/"
      @token = JSON.parse(File.read(@fixtures + "ec_v1/tokenized_card.json"))
      @private_key = File.read(@fixtures + "google_pay_token_private_key.pem")
      @verification_keys = JSON.parse(File.read(@fixtures + "verification_keys/google_verification_key_test.json"))
      Timecop.freeze(Time.at(1509713963))
    end

    def teardown
      Timecop.return
    end

    def test_decrypted_tokenized_card
      expected = {
        "messageExpiration" => "1510318759535",
        "paymentMethod" => "TOKENIZED_CARD",
        "messageId" => "AH2EjtfMnpeHvgqYbBDLAxPzyYlPOmOa792BqdsvTc2T7jsn23_us0dKU509I-AA9dVDLf9_v4c5ldxoge6Q3iYr9acGGSyD9ojbOTP1fjWzDteVE_yf1pGzGNQ2Q6jKG96KRpbIaziY",
        "paymentMethodDetails" =>
          {
            "expirationYear" => 2022,
            "dpan" => "4895370012003478",
            "expirationMonth" => 12,
            "authMethod" => "3DS",
            "3dsCryptogram" => "AgAAAAAABk4DWZ4C28yUQAAAAAA=",
            "3dsEciIndicator" => "07"
          }
      }
      decrypted = new_token.decrypt(@private_key)

      assert_equal expected, decrypted
    end

    def test_decrypted_card
      @token = JSON.parse(File.read(@fixtures + 'ec_v1/card.json'))
      expected = {
        "messageExpiration" => "1510319499834",
        "paymentMethod" => "CARD",
        "messageId" => "AH2EjtcMeg5mOCD9kUXWn6quP6AF6jOJeirO0EW40tPVzMMy_YAri8HZdJzqzQquC0w_dkvXhC41s2BN53HRD_kzgT4jxGeB4E9BI8OQCPw9GgWTXIAQb55Av77l6VCesYHIQre8Ij60",
        "paymentMethodDetails" =>
          {
            "expirationYear" => 2022,
            "expirationMonth" => 12,
            "pan" => "4111111111111111"
          }
      }
      decrypted = new_token.decrypt(@private_key)

      assert_equal expected, decrypted
    end

    def test_wrong_signature
      @token['signature'] = "MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagCCgHlCk3NcFwWYEyxIE6KGZVA\u003d\u003d"

      assert_raises R2D2::SignatureInvalidError do
        new_token.decrypt(@private_key)
      end
    end

    def test_wrong_verification_key
      @verification_keys = JSON.parse(File.read(@fixtures + "verification_keys/google_verification_key_production.json"))

      assert_raises R2D2::SignatureInvalidError do
        new_token.decrypt(@private_key)
      end
    end

    def test_unknown_verification_key_version
      @verification_keys = JSON.parse(File.read(@fixtures + "verification_keys/bad_google_verification_key_test.json"))

      assert_raises R2D2::SignatureInvalidError do
        new_token.decrypt(@private_key)
      end
    end

    def test_multiple_verification_keys
      production_keys = JSON.parse(File.read(@fixtures + "verification_keys/google_verification_key_production.json"))['keys']
      @verification_keys = { 'keys' => production_keys + @verification_keys['keys'] }

      assert new_token.decrypt(@private_key)
    end

    def test_expired_message
      Timecop.freeze(Time.at(1510318760)) do
        assert_raises R2D2::MessageExpiredError do
          new_token.decrypt(@private_key)
        end
      end
    end

    private

    def new_token
      R2D2::GooglePayToken.new(
        @token,
        recipient_id: @recipient_id,
        verification_keys: @verification_keys
      )
    end
  end
end
