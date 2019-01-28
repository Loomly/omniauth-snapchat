require 'omniauth/strategies/oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class Snapchat < OmniAuth::Strategies::OAuth2

      option :name, "snapchat"

      option :client_options, {
        :site          => 'https://adsapi.snapchat.com',
        :authorize_url => 'https://accounts.snapchat.com/login/oauth2/authorize',
          :token_url => 'https://accounts.snapchat.com/accounts/oauth2/token'
      }

      uid{ raw_info['me']['externalId'] }

      info do
        {
          name: raw_info['me']['displayName'],
          image: raw_info['me']['bitmoji']['avatar']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        # After back and forth with snapchat support team, using the GraphQL
        # endpoint seems the easiest.
        raw_info_url = "https://kit.snapchat.com/v1/me?query=%7Bme%7BexternalId%2C+displayName%2C+bitmoji%7Bavatar%7D%7D%7D"
        @raw_info ||= access_token.get(raw_info_url).parsed["data"]
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def token_params
        authorization = Base64.strict_encode64("#{options.client_id}:#{options.client_secret}")
        super.merge({
                        headers: {
                            'Authorization' => "Basic #{authorization}"
                        }
                    })
      end
    end
  end
end
