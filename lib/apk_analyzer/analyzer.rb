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
        application_content = {}
        application_name = @manifest_xml.xpath('//application/@android:name')
        application_content[:application_name] = application_name
        application_id = @manifest_xml.xpath('//manifest/@package')
        application_content[:application_id] = application_id
        intent_filters = @manifest_xml.xpath('//intent-filter')
        puts intent_filters
        intents = []
        intent_filters.each do |intent|
          intent_attributes = {}
          actions = []
          category = nil
          intent.children.each do |child|
            puts child if child.is_a?(Nokogiri::XML::Element)
            next unless child.is_a?(Nokogiri::XML::Element)
            if child.name == 'action'
              actions.push child.attributes['name'].value
            elsif child.name == 'category'
              category = child.attributes['name'].value
            end
            intent_attributes[:actions] = actions
            intent_attributes[:category] = category
          end
          intents.push intent_attributes
        end
        content[:intents] = intents
        # sdk infos
        minimum_sdk_version = @manifest_xml.xpath('//uses-sdk/@android:minSdkVersion')
        target_sdk_version = @manifest_xml.xpath('//uses-sdk/@android:targetSdkVersion')
        data = [minimum_sdk_version, target_sdk_version].map { |elt| sanitize_hex(elt.first.value) unless elt.empty? }
        content[:uses_sdk] = { minimum_sdk_version: data[0], target_sdk_version: data[1] }

        # uses permission
        content[:uses_permissions] = []
        @manifest_xml.xpath('//uses-permission/@android:name').each { |permission| content[:uses_permissions].push permission.value }

        # uses features
        content[:uses_features] = []
        features = @manifest_xml.xpath('//uses-feature')
        feature_list = []
        features.each do  |feature|
          feature_element = {}
          feature.attributes.each_value do |attr|
            value = attr.value
            value = bool_conv(value) if attr.name == 'required'
            if attr.name == 'glEsVersion'
              feature_element[:name] = open_gl_version_conv(attr.value)
            else
              feature_element[attr.name.to_sym] = value
            end
          end
          feature_list.push feature_element
        end
        content[:uses_features] = feature_list

        # screen compatibility
        content[:supports_screens] = []
        screen_types = @manifest_xml.xpath('//supports-screens').first
        screen_types.attributes.each { |attr_name, attr_object| content[:supports_screens].push attr_name unless attr_object.value == FALSE } unless screen_types.nil?
        manifest_info[:content] = content
      end
    end

    private

    def sanitize_hex(hex)
      hex.to_i(16)
    end

    def bool_conv(value)
      value == FALSE ? 'false' : 'true'
    end

    def open_gl_version_conv(value)
      value_copy = value.dup
      value_copy = value_copy.gsub(/\D|0/, '')
      value_copy.chars.join('.')
      value_copy += '.0' if value.chars.last == '0'
      value_copy
=begin
      opengl = 'OpenGL ES '
      opengl +
              case value
              when '0x10000'
                '1.0'
              when '0x10001'
                '1.1'
              when '0x20000'
                '2.0'
              when '0x20001'
                '2.1'
              when '0x30000'
                '3.0'
              when '0x30001'
                '3.1'
              end
=end
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
