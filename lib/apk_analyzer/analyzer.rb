require 'apktools/apkxml'
require 'nokogiri'
require 'mkmf'

module ApkAnalyzer
  class Analyzer
    FALSE = '0x0'.freeze

    def initialize(apk_path)
      @apk_path = apk_path
      raise 'File is not a valid apk file' unless valid_zip?(apk_path)
      @apk_xml = ApkXml.new(apk_path)
    end

    def collect_manifest_info
      manifest_file_path = find_file_in_apk('AndroidManifest.xml')
      raise 'Failed to find Manifest file in apk' if manifest_file_path.nil?
      manifest_xml = Nokogiri::XML(@apk_xml.parse_xml('AndroidManifest.xml', true, true))
      {}.tap do |manifest_info|
        manifest_info[:path_in_apk] = manifest_file_path
        content = {}
        # application content
        content[:application_info] = collect_application_info(manifest_xml)

        # intents
        content[:intents] = collection_intent_info(manifest_xml)

        # sdk infos
        sdk_infos = collect_sdk_info(manifest_xml)
        content[:uses_sdk] = { minimum_sdk_version: sdk_infos[0], target_sdk_version: sdk_infos[1] }

        # uses permission
        uses_permissions = collect_uses_permission_info(manifest_xml)
        content[:uses_permissions] = uses_permissions

        # uses features
        feature_list = collect_uses_feature_info(manifest_xml)
        content[:uses_features] = feature_list

        # screen compatibility
        supported_screens = collect_supported_screens(manifest_xml)
        content[:supports_screens] = supported_screens

        manifest_info[:content] = content
      end
    end

    def collect_supported_screens(manifest_xml)
      supported_screens = []
      screen_types = manifest_xml.xpath('//supports-screens').first
      unless screen_types.nil?
        screen_types.attributes.each { |attr_name, attr_object| supported_screens.push attr_name unless attr_object.value == FALSE }
      end
      supported_screens
    end

    def collect_uses_feature_info(manifest_xml)
      features = manifest_xml.xpath('//uses-feature')
      feature_list = []
      features.each do  |feature|
        feature_element = {}
        feature.attributes.each_value do |attr|
          value = attr.value
          value = bool_conv(value) if attr.name == 'required'
          if attr.name == 'glEsVersion'
            feature_element[:name] = opengl_version_conv(attr.value)
          else
            feature_element[attr.name.to_sym] = value
          end
        end
        feature_list.push feature_element
      end
      feature_list
    end

    def collect_uses_permission_info(manifest_xml)
      uses_permissions = []
      manifest_xml.xpath('//uses-permission/@android:name').each { |permission| uses_permissions.push permission.value }
      uses_permissions
    end

    def collect_application_info(manifest_xml)
      application_content = {}
      application_name = manifest_xml.xpath('//application')
      return application_content if application_name.empty?
      application_attributes = application_name.first.attributes
      application_attributes.each_value do |application_attribute|
        value = application_attribute.value
        value = bool_conv(value) if value == '0x0' || value == '0xffffffff'
        application_content[application_attribute.name.to_sym] = value
      end
      application_id = manifest_xml.xpath('//manifest/@package')
      application_content[:application_id] = application_id[0].value unless application_id.empty?
      application_content
    end

    def collection_intent_info(manifest_xml)
      intent_filters = manifest_xml.xpath('//intent-filter')
      intents = []
      intent_filters.each do |intent|
        intent_attributes = {}
        actions = []
        category = nil
        intent.children.each do |child|
          next unless child.is_a?(Nokogiri::XML::Element)
          if child.name == 'action'
            actions.push child.attributes['name'].value
          elsif child.name == 'category'
            category = child.attributes['name'].value
          end
        end
        intent_attributes[:actions] = actions unless actions.empty?
        intent_attributes[:category] = category unless category.nil?
        intents.push intent_attributes unless intent_attributes.empty?
      end
      intents
    end

    def collect_sdk_info(manifest_xml)
      minimum_sdk_version = manifest_xml.xpath('//uses-sdk/@android:minSdkVersion')
      target_sdk_version = manifest_xml.xpath('//uses-sdk/@android:targetSdkVersion')
      sdk_infos = [minimum_sdk_version, target_sdk_version].map { |elt| sanitize_hex(elt.first.value) unless elt.empty? }
      sdk_infos
    end

    # Certificate info. Issuer and dates
    def collect_cert_info
      # raise 'keytool dependency not satisfied. Make sure you have installed keytool command utility' if find_executable('keytool').nil?
      raise 'keytool dependency not satisfied. Make sure you have installed keytool command utility' if `which keytool` == nil
      certificate_raw = `keytool -printcert -rfc -jarfile #{@apk_path}`
      certificate_content_regexp = /(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----)/m

      cert_info = {
        issuer_raw: nil,
        cn: nil,
        ou: nil,
        o: nil,
        st: nil,
        l: nil,
        c: nil,
        creation_date: nil,
        expiration_date: nil
      }

      cert_rsa = find_file_in_apk('CERT.RSA')
      if cert_rsa.nil?
        puts 'Failed to find certificate file in APK'
        return {}
      end
      certificate_content = certificate_content_regexp.match(certificate_raw).captures[0]
      cert_extract_dates(certificate_content, cert_info)
      cert_extract_issuer(certificate_content, cert_info)
      cert_info.each do |key, value|
        cert_info[key] = value.gsub(/\n/,'') unless value.nil?
      end
      cert_info
    end

    private

    def cert_extract_issuer(certificate_content, result)
      subject = `echo "#{certificate_content}" | openssl x509 -noout -in /dev/stdin -subject -nameopt -esc_msb,utf8`
      result[:issuer_raw] = subject
      result[:ou] = cert_extract_issuer_parameterized(subject, 'OU')
      result[:cn] = cert_extract_issuer_parameterized(subject, 'CN')
      result[:o] = cert_extract_issuer_parameterized(subject, 'O')
      result[:st] = cert_extract_issuer_parameterized(subject, 'ST')
      result[:l] = cert_extract_issuer_parameterized(subject, 'L')
      result[:c] = cert_extract_issuer_parameterized(subject, 'C')
    end


    def cert_extract_dates(certificate_content, result)
      #collect dates
      start_date = `echo "#{certificate_content}" | openssl x509 -noout -in /dev/stdin -startdate -nameopt -esc_msb,utf8`
      end_date = `echo "#{certificate_content}" | openssl x509 -noout -in /dev/stdin -enddate -nameopt -esc_msb,utf8`
      result[:creation_date] = cert_extract_date(start_date)
      result[:expiration_date] = cert_extract_date(end_date)
    end

    def cert_extract_date(date_str)
      match = /=(.*)$/.match(date_str)
      match.captures[0]
    end

    def cert_extract_issuer_parameterized(subject, param)
      # The following regex was previously used to match fields when not
      # using '-nameopt -esc_msb,utf8'' switch with openssl
      # match = %r{\/#{Regexp.quote(param)}=([^\/]*)}.match(subject)

      match = /#{Regexp.quote(param)}=([^=]*)(, [A-Z]+=|$)/.match(subject)
      return nil if match.nil?
      match.captures[0]
    end

    def cert_extract_date(date_str)
      match = /=(.*)$/.match(date_str)
      match.captures[0]
    end

    def sanitize_hex(hex)
      hex.to_i(16)
    end

    def bool_conv(value)
      value == FALSE ? false : true
    end

    def opengl_version_conv(value)
      value_copy = value.dup
      value_copy = value_copy.gsub(/\D|0/, '')
      value_copy.chars.join('.')
      value_copy += '.0' if value.chars.last == '0'
      "Open GL #{value_copy}"
    end

    def valid_zip?(file)
      zip = Zip::File.open(file)
      true
    rescue StandardError
      false
    ensure
      zip.close if zip
    end

    def find_file_in_apk(file_name)
      begin
        file_path_in_apk = nil
        apk_zipfile = Zip::File.open(@apk_path)

        # Search at the root
        file_path_in_apk = apk_zipfile.find_entry(file_name)
        return file_path_in_apk.name unless file_path_in_apk.nil?

        # Search deeply
        apk_zipfile.each do |entry|
          file_path_in_apk = entry.name if entry.name.match(file_name)
          break unless file_path_in_apk.nil?
        end
        file_path_in_apk.nil? ? nil : file_path_in_apk.name
      rescue => e
        raise e.message
      ensure
        apk_zipfile.close
      end
    end
  end
end
