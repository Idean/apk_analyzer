require 'apktools/apkxml'
require 'nokogiri'
module ApkAnalyzer
  class Analyzer
    FALSE = '0x0'.freeze

    def initialize(apk_path)
      @apk_path = apk_path
      @apk_xml = ApkXml.new(apk_path)
    rescue
      raise 'Apk is not valid'
    end

    def open
      @manifest_xml = Nokogiri::XML(@apk_xml.parse_xml('Manifest.xml'))
      puts @manifest_xml
    rescue => e
      raise 'Apk is not valid'
    end

    def open?
      !@manifest_xml.nil?
    end

    def collect_manifest_info
      raise 'Apk is not open' unless open?
      {}.tap do |manifest_info|
        manifest_info[:path_in_apk] = find_file_in_apk('AndroidManifest.xml')
        content = {}
        # application content
        content[:application_info] = collect_application_info(@manifest_xml)

        # intents
        content[:intents] = collection_intent_info(@manifest_xml)

        # sdk infos
        sdk_infos = collect_sdk_info(@manifest_xml)
        content[:uses_sdk] = { minimum_sdk_version: sdk_infos[0], target_sdk_version: sdk_infos[1] }

        # uses permission
        uses_permissions = collect_uses_permission_info(@manifest_xml)
        content[:uses_permissions] = uses_permissions

        # uses features
        feature_list = collect_uses_feature_info(@manifest_xml)
        content[:uses_features] = feature_list

        # screen compatibility
        supported_screens = collect_supported_screens(@manifest_xml)
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
      application_name = manifest_xml.xpath('//application/@android:name')
      application_content[:application_name] = application_name
      application_id = manifest_xml.xpath('//manifest/@package')
      application_content[:application_id] = application_id
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
        intents.push intent_attributes
      end
      intents
    end

    def collect_sdk_info(manifest_xml)
      minimum_sdk_version = manifest_xml.xpath('//uses-sdk/@android:minSdkVersion')
      target_sdk_version = manifest_xml.xpath('//uses-sdk/@android:targetSdkVersion')
      sdk_infos = [minimum_sdk_version, target_sdk_version].map { |elt| sanitize_hex(elt.first.value) unless elt.empty? }
      sdk_infos
    end


    private

    def sanitize_hex(hex)
      hex.to_i(16)
    end

    def bool_conv(value)
      value == FALSE ? 'false' : 'true'
    end

    def opengl_version_conv(value)
      value_copy = value.dup
      value_copy = value_copy.gsub(/\D|0/, '')
      value_copy.chars.join('.')
      value_copy += '.0' if value.chars.last == '0'
      "Open GL #{value_copy}"
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
        file_path_in_apk.name
      rescue => e
        raise e.message
      ensure
        apk_zipfile.close
      end
    end
  end
end
