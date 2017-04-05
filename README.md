[![Build Status](https://travis-ci.org/Backelite/apk_analyzer.svg?branch=master)](https://travis-ci.org/Backelite/apk_analyzer)

# Apk Analyzer

The aim of this gem is to extract some data from android apk files. Analysis results are printed in json. It can be used with CLI

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'apk_analyzer'
```

And then execute:

```shell
$ bundle
```

Or install it yourself as:

```shell
$ gem install apk_analyzer
```

## Usage

1. **CLI Usage**

In a terminal use Apk analyzer like this:

```shell
$ apk_analyzer --manifest --cert-info --file /path/to/apk
```

Script above will collect and print:
* Android manifest informations
* Apk certificate informations if it have been signed

**Result**
```json
{
  "manifest_info": {
    "path_in_apk": "AndroidManifest.xml",
    "content": {
      "application_info": {
        "theme": "13",
        "label": "E.app.label",
        "icon": "@drawable/ic_launcher",
        "name": "com.package.xxxx.xxxx",
        "debuggable": true,
        "allowBackup": true,
        "hardwareAccelerated": true,
        "application_id": "com.xxxxxxx.xxxx.xxx"
      },
      "intents": [
        {
          "actions": [
            "android.intent.action.MAIN"
          ],
          "category": "android.intent.category.LAUNCHER"
        },
        {
          "actions": [
            "com.android.vending.INSTALL_REFERRER"
          ]
        },
        {
          "actions": [
            "com.google.android.c2dm.intent.RECEIVE",
            "com.google.android.c2dm.intent.REGISTRATION"
          ],
          "category": "com.xxxxxx.xxx.rec"
        },
        {
          "actions": [
            "com.google.firebase.INSTANCE_ID_EVENT"
          ]
        }
      ],
      "uses_sdk": {
        "minimum_sdk_version": 14,
        "target_sdk_version": 23
      },
      "uses_permissions": [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.VIBRATE",
        "com.google.android.c2dm.permission.RECEIVE",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.WAKE_LOCK",
        "com.modulotech.xxxxxxx.xxxx.permission.C2D_MESSAGE"
      ],
      "uses_features": [
        {
          "name": "android.hardware.camera",
          "required": true
        }
      ],
      "supports_screens": [
        "anyDensity",
        "normalScreens",
        "largeScreens",
        "xlargeScreens"
      ]
    }
  },
  "cert_info": {
    "issuer_raw": "subject= C=US, O=Android, CN=Android Debug",
    "cn": "Android Debug",
    "ou": null,
    "o": "Android",
    "st": null,
    "l": null,
    "c": "US",
    "creation_date": "Sep 15 07:06:03 2011 GMT",
    "expiration_date": "Sep  7 07:06:03 2041 GMT"
  }
}
```

2. **Inside Ruby code**

```ruby
require 'apk_analyzer'

# Instantiate analyzer
apk_analyzer = ApkAnalyzer::Analyzer.new(File.expand_path('path/to/apk'))

# Then collect data
manifest_info = apk_analyzer.collect_manifest_info
certificate_info = apk_analyzer.collect_cert_info
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Backelite/apk_analyzer.

## Requirements

* Java keytool: Java and its keytool utility must be installed and set in the PATH on your OS
* OpenSSL: version 1.0.2g (1 Mar 2016) or greater

## Known issues

To avoid rubyzip 'Invalid date/time in zip entry' message logged by rubzip dependency on [apktools](https://github.com/devunwired/apktools) gem we updated it in our gem and set
warn_invalid_date to false.
A [pull request](https://github.com/devunwired/apktools/pull/20) is pending to correct this on apkxml gem too.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
