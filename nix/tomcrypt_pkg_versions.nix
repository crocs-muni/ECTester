{ buildECTesterStandalone }:
{
  v1182 = buildECTesterStandalone {
    tomcrypt = {
      version = "1.18.2";
      hash = "sha256-MEU+u54aXKGSAMPYsh+L9axowzIHiew1uWq8wDsEBmw=";
    };
    tommath = {
      version = "1.3.0";
      hash = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg=";
    };
  };
  v1181 = buildECTesterStandalone {
    tomcrypt = {
      version = "1.18.1";
      hash = "sha256-P00koc4+mAHQ/L5iCuPoiOeI/msZscO5KHZrqmbotRo=";
    };
    tommath = {
      version = "1.3.0";
      hash = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg=";
    };
  };
  v1180 = buildECTesterStandalone {
    tomcrypt = {
      version = "1.18.0";
      hash = "sha256-Y7U+updJI/f3zD6k84DTZDQZh6vhfqR0W8HyizlUZcU=";
    };
    tommath = {
      version = "1.3.0";
      hash = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg=";
    };
  };
  # v101 = buildECTesterStandalone {
  #   tomcrypt = { version = "1.01"; hash = "sha256-lVAPxgkAcBivzZmWfqu0sEh8yGo7Ji2hIYwx4/g0GzM=";};
  #   tommath = { version = "1.3.0"; hash = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg="; };
  # }; 
  v117 = buildECTesterStandalone {
    tomcrypt = {
      version = "1.17";
      hash = "sha256-NWWAs6p27UC64nDL0MwMvzU5aWNe8LZu7DC06d/8isA=";
    };
    # NOTE: which is the correct version of libtommath for a particular version of libtomcryp?
    tommath = {
      version = "1.3.0";
      hash = "sha256-KWJy2TQ1mRMI63NgdgDANLVYgHoH6CnnURQuZcz6nQg=";
    };
  };
}
