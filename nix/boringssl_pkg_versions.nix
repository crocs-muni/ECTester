{
  buildECTesterStandalone
}:
{ 
# "version_for_cocoapods_10.0",

# "version_for_cocoapods_9.0",
# "version_for_cocoapods_8.0",
# "version_for_cocoapods_7.0",
# "version_for_cocoapods_6.0",
# "version_for_cocoapods_5.0",
# "version_for_cocoapods_4.0",
# "version_for_cocoapods_3.0",
# "version_for_cocoapods_2.0",
# "version_for_cocoapods_1.0",
# "fips-android-20191020",
# "fips-20220613",
# "fips-20210429",
# "fips-20190808",
# "fips-20180730",
  fips-20170615 = buildECTesterStandalone {
    boringssl = { rev = "refs/tags/fips-20170615"; hash = ""; };
  };
}
