require 'apktools/apkxml'
require 'nokogiri'
require 'shellwords'

module ApkAnalyzer
  class Analyzer
    HEX_FALSE = '0x0'.freeze
    HEX_TRUE = '0xffffffff'.freeze
    REQUIRED = 'required'.freeze
    GL_ES_VERSION = 'glEsVersion'
    NAME = 'name'
    ACTION = 'action'
    CATEGORY = 'category'
    ANDROID_MANIFEST_FILE = 'AndroidManifest.xml'


    def initialize(file_path)
      # Deactivating invalid date warnings in zip for apktools gem and apk analyzer code
      Zip.warn_invalid_date = false
      @file_path = file_path
      raise 'File is not a valid file' unless valid_zip?(file_path)
      case File.extname(file_path)
      when ".apk"
        @manifest = ApkXml.new(file_path).parse_xml('AndroidManifest.xml', true, true)
      when ".aab"
        String bundle_tool_location = %x[ #{"which bundletool"} ]
        raise 'Bundletool is not installed & available in your path' if bundle_tool_location.nil? or bundle_tool_location.length == 0
        cmd = "bundletool dump manifest --bundle #{file_path}"
        @manifest = %x[ #{cmd} ]
      else
        raise 'unknown platform technology'
      end
    end

    def collect_manifest_info
      manifest_file_path = find_file(ANDROID_MANIFEST_FILE)
      raise 'Failed to find Manifest file' if manifest_file_path.nil?
      begin
        manifest_xml = Nokogiri::XML(@manifest)
      rescue => e
        puts "Failed to parse #{ANDROID_MANIFEST_FILE}"
        log_expection e
      end

      manifest_info = {}
      begin
        manifest_info[:path] = manifest_file_path
        content = {}
        # application content
        content[:application_info] = collect_application_info(manifest_xml)

        # intents
        content[:intents] = collect_intent_info(manifest_xml)

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
      rescue => e
        log_expection e
        raise "Invalid xml found"
      end
      manifest_info
    end
    
    # Certificate info. Issuer and dates
    def collect_cert_info
      # Redirect keytool check error to /dev/null
      os_has_keytool = system('keytool 2>/dev/null')
      raise 'keytool dependency not satisfied. Make sure that JAVA keytool utility is installed' unless os_has_keytool
      cert_info = {}
      certificate_raw = `keytool -printcert -rfc -jarfile #{@file_path.shellescape}`
      certificate_content_regexp = /(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----)/m
      matched_data = certificate_content_regexp.match(certificate_raw)
      if matched_data
        certificate_content = matched_data.captures[0]
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
        cert_extract_dates(certificate_content, cert_info)
        cert_extract_issuer(certificate_content, cert_info)
      else
        puts 'Failed to find CERT.RSA file'
      end
      cert_info
    end

    private

    def collect_supported_screens(manifest_xml)
      supported_screens = []
      screen_types = manifest_xml.xpath('//supports-screens').first
      unless screen_types.nil?
        screen_types.attributes.each do |screen_type, required_param|
          supported_screens.push screen_type if required_param.value == HEX_TRUE
        end
      end
      supported_screens
    end

    def collect_uses_feature_info(manifest_xml)
      features = manifest_xml.xpath('//uses-feature')
      feature_list = []
      features.each do  |feature|
        feature_element = {}
        feature.attributes.each_value do |attr|
          feature_attr_key = attr.name
          feature_attr_value = attr.value

          if attr.name == REQUIRED
            feature_attr_value = bool_conv(feature_attr_value)
          elsif attr.name == GL_ES_VERSION
            feature_attr_key = NAME
            feature_attr_value = opengl_version_conv(attr.value)
          end

          feature_element[feature_attr_key.to_sym] = feature_attr_value
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
      application_tag = manifest_xml.xpath('//application')

      # Collect all attributes within application tag
      unless application_tag.empty?
        application_attributes = application_tag.first.attributes
        application_attributes.each_value do |attr_key|
          value = attr_key.value
          value = bool_conv(value) if is_hex_bool?(value)
          application_content[attr_key.name.to_sym] = value
        end
      end

      # Add application id to previous informations
      application_id = manifest_xml.xpath('//manifest/@package')
      application_content[:application_id] = application_id[0].value unless application_id.empty?

      application_content
    end

    def collect_intent_info(manifest_xml)
      intent_filters = manifest_xml.xpath('//intent-filter')
      intents = []
      intent_filters.each do |intent|
        intent_attributes = {}
        actions = []
        category = nil
        intent.children.each do |child|
          next unless child.is_a?(Nokogiri::XML::Element)
          if child.name == ACTION
            actions.push child.attributes[NAME].value
          elsif child.name == CATEGORY
            category = child.attributes[NAME].value
          end
        end
        intent_attributes[:actions] = actions unless actions.empty?
        intent_attributes[:category] = category unless category.nil?
        intents.push intent_attributes unless intent_attributes.empty?
      end
      intents
    end

    def collect_sdk_info(manifest_xml)
      sdk_infos = []
      minimum_sdk_version = manifest_xml.xpath('//uses-sdk/@android:minSdkVersion')
      target_sdk_version = manifest_xml.xpath('//uses-sdk/@android:targetSdkVersion')
      sdk_infos = [minimum_sdk_version, target_sdk_version].map { |elt| sanitize_hex(elt.first.value) unless elt.empty? }
      sdk_infos
    end

    def cert_extract_issuer(certificate_content, result)
      print(certificate_content)
      subject = `echo "#{certificate_content}" | openssl x509 -noout -in /dev/stdin -subject -nameopt -esc_msb,utf8`
      # All certificate fields are not manadatory. At least one is needed.So to remove trailing carrier return
      # character, we apply gsub method on the raw subject, and we use it after.
      raw = subject.gsub(/\n/,'')
      result[:issuer_raw] = raw
      result[:cn] = cert_extract_issuer_parameterized(raw, 'CN')
      result[:ou] = cert_extract_issuer_parameterized(raw, 'OU')
      result[:o] = cert_extract_issuer_parameterized(raw, 'O')
      result[:st] = cert_extract_issuer_parameterized(raw, 'ST')
      result[:l] = cert_extract_issuer_parameterized(raw, 'L')
      result[:c] = cert_extract_issuer_parameterized(raw, 'C')
    end

    def cert_extract_issuer_parameterized(subject, param)
      # The following regex was previously used to match fields when not
      # using '-nameopt -esc_msb,utf8'' switch with openssl
      # match = %r{\/#{Regexp.quote(param)}=([^\/]*)}.match(subject)

      match = /#{Regexp.quote(param)}=([^=]*)(, [A-Z]+=|$)/.match(subject)
      return nil if match.nil?
      match.captures[0]
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

    def sanitize_hex(hex)
      hex.to_i(16)
    end

    # hex strings come come from apktools/apkxml.
    # It converts true to 0xffffffff and false to 0x0
    def bool_conv(value)
      value == HEX_FALSE ? false : true
    end

    def is_hex_bool?(hex_string)
      hex_string == HEX_TRUE || hex_string == HEX_FALSE
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

    def find_file(file_name)
      begin
        zipfile = Zip::File.open(@file_path)

        # Search at the root
        file_path = zipfile.find_entry(file_name)
        return file_path.name unless file_path.nil?

        # Search deeply
        zipfile.each do |entry|
          file_path = entry.name if entry.name.match(file_name)
          break unless file_path.nil?
        end
        file_path.nil? ? nil : file_path
      rescue => e
        log_expection e
      ensure
        zipfile.close
      end
    end

    def log_expection e
      puts e.message
      puts e.backtrace
    end
  end
end
