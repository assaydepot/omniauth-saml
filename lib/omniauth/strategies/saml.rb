require 'omniauth'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy
      autoload :AuthRequest,      'omniauth/strategies/saml/auth_request'
      autoload :AuthResponse,     'omniauth/strategies/saml/auth_response'
      autoload :ValidationError,  'omniauth/strategies/saml/validation_error'
      autoload :XMLSecurity,      'omniauth/strategies/saml/xml_security'
      autoload :MetadataResponse, 'omniauth/strategies/saml/metadata_response'

      option :name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      def request_phase
        request = OmniAuth::Strategies::SAML::AuthRequest.new
        redirect(request.create(options))
      end

      def callback_phase
        begin
          response = OmniAuth::Strategies::SAML::AuthResponse.new(request.params['SAMLResponse'])
          response.settings = options

          @name_id  = response.name_id
          @attributes = response.attributes

          begin
            response.valid? # to generate some errbit info for Xavier
          rescue => e
            if defined?(Airbrake)
              Airbrake.notify(e,
                {:base64_response => request.params['SAMLResponse'],
                 :response_decoded => response.document.inspect,
                 :note => "Xavier is trying to figure out why AZ's requests are breaking omniauth-saml"}
              )
            end
          end
          return fail!(:invalid_ticket, OmniAuth::Error.new('Invalid SAML Ticket')) if @name_id.nil? || @name_id.empty? # || !response.valid?
          super
        rescue ArgumentError => e
          fail!(:invalid_ticket, e)
        end
      end

      def other_phase
        if on_path?("#{request_path}/metadata")
          response = OmniAuth::Strategies::SAML::MetadataResponse.new
          Rack::Response.new(response.create(options), 200, { "Content-Type" => "application/xml" })
        else
          call_app!
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes[:name],
          :email => @attributes[:email] || @attributes[:mail],
          :first_name => @attributes[:first_name] || @attributes[:firstname],
          :last_name => @attributes[:last_name] || @attributes[:lastname]
        }
      end

      extra { { :raw_info => @attributes } }

    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
