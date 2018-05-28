require "test_helper"

module R2D2
  class TokenBuilderTest < Minitest::Test
    def setup
      @fixtures = __dir__ + "/fixtures/"
      @recipient_id = 'merchant:12345678901234567890'
      @verification_keys = JSON.parse(File.read(@fixtures + "ec_v1/google_verification_key_test.json"))
    end

    def test_builds_android_pay_token
      token_attrs = JSON.parse(File.read(@fixtures + "token.json"))
      assert_instance_of AndroidPayToken, R2D2.build_token(token_attrs)
    end

    def test_builds_google_pay_token
      token_attrs = JSON.parse(File.read(@fixtures + "ec_v1/tokenized_card.json"))
      assert_instance_of GooglePayToken, R2D2.build_token(token_attrs, recipient_id: @recipient_id, verification_keys: @verification_keys)
    end

    def test_building_token_raises_with_unknown_protocol_version
      token_attrs = JSON.parse(File.read(@fixtures + "ec_v1/tokenized_card.json"))
      token_attrs['protocolVersion'] = 'foo'

      assert_raises ArgumentError do
        R2D2.build_token(token_attrs, recipient_id: @recipient_id, verification_keys: @verification_keys)
      end
    end

    def test_building_google_pay_token_raises_with_missing_arguments
      token_attrs = JSON.parse(File.read(@fixtures + "ec_v1/tokenized_card.json"))
      assert_raises ArgumentError do
        R2D2.build_token(token_attrs)
      end
    end
  end
end
