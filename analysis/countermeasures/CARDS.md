This document summarizes the cards tested during our analysis.

Note that several smartcards really are the same model and thus we merged them in the paper:
 - N4 = N5 = N10
 - N6 = N7
 - N3 = N8

# NXP

## N1

**Name**: NXP J3A081 JCOP v2.4.1
**Card ATR**: `3B F8 18 00 FF 81 31 FE 45 4A 43 4F 50 76 32 34 31 43`

```
CPLC: ICFabricator=4790
      ICType=5168
      OperatingSystemID=4791
      OperatingSystemReleaseDate=0078 (2010-03-19)
      OperatingSystemReleaseLevel=3400
      ICFabricationDate=1329 (2011-11-25)
      ICSerialNumber=01447395
      ICBatchIdentifier=7689
      ICModuleFabricator=4812
      ICModulePackagingDate=1336 (2011-12-02)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (2010-01-01)
      ICPrePersonalizer=092C
      ICPrePersonalizationEquipmentDate=2D31 (invalid date format)
      ICPrePersonalizationEquipmentID=34343733
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.2.21
-> GP SCP02 i=15
Tag 65: 1.3.656.840.100.2.1.3
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
Card Capabilities: 
Version: 255 (0xFF) ID:   1 (0x01) type: DES3 length:  16 
Version: 255 (0xFF) ID:   2 (0x02) type: DES3 length:  16 
Version: 255 (0xFF) ID:   3 (0x03) type: DES3 length:  16 
Key version suggests factory keys
```

## N2

**Name**: NXP JCOP v2.4.1R3
**Card ATR**: `3B F8 13 00 00 81 31 FE 45 4A 43 4F 50 76 32 34 31 B7`
 
```
CPLC: ICFabricator=4790
      ICType=5167
      OperatingSystemID=4791
      OperatingSystemReleaseDate=0078 (2020-03-18)
      OperatingSystemReleaseLevel=3400
      ICFabricationDate=2240 (2022-08-28)
      ICSerialNumber=00032096
      ICBatchIdentifier=2581
      ICModuleFabricator=4812
      ICModulePackagingDate=2247 (2022-09-04)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (invalid date format)
      ICPrePersonalizer=0938
      ICPrePersonalizationEquipmentDate=0C30 (invalid date format)
      ICPrePersonalizationEquipmentID=30333230
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (invalid date format)
      ICPersonalizationEquipmentID=00000000

KDD: CF0A00002240000320962581
SSC: C1020166
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
Tag 6: 1.2.840.114283.4.2.21
-> GP SCP02 (i=15)
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
```

## N3

**Name**: NXP JCOP v2.4.2 R3 J2E145G

## N4 

**Name**: NXP JCOP3 J3H145
**Card ATR**: `3B 94 95 81 01 46 54 56 01 C4`
**IDENTIFY response**: `010c0032423245a805d840a842290208030000000000000003104a7848797979303031393739303430300408c3762e82db03cb58050137` -> JxHyyy0019790400

```
CPLC: ICFabricator=4790
      ICType=0503
      OperatingSystemID=8211
      OperatingSystemReleaseDate=6351 (2016-12-16)
      OperatingSystemReleaseLevel=0302
      ICFabricationDate=8359 (2018-12-25)
      ICSerialNumber=01498607
      ICBatchIdentifier=4673
      ICModuleFabricator=4E30
      ICModulePackagingDate=5038 (2015-02-07)
      ICCManufacturer=3532
      ICEmbeddingDate=4246 (2014-09-03)
      ICPrePersonalizer=4A31
      ICPrePersonalizationEquipmentDate=3031 (2013-01-31)
      ICPrePersonalizationEquipmentID=34393836
      ICPersonalizer=0600
      ICPersonalizationDate=0123 (2010-05-03)
      ICPersonalizationEquipmentID=B1BB6E97

IIN: 420100
CIN: 45080000000000000000
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.2.85
-> GP SCP02 i=55
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
Card Capabilities: 
Supports: SCP02 i=55
Supports: SCP03 i=00 i=10 with AES-128 AES-196 AES-256
Supported DOM privileges: SecurityDomain, CardLock, CardTerminate, CardReset, CVMManagement, TrustedPath, AuthorizedManagement, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, FinalApplication, GlobalService
Supported LFDB hash: 02
Supported Token Verification ciphers: 01020840
Supported Receipt Generation ciphers: 0408
Supported DAP Verification ciphers: 01020840
Supported ECC Key Parameters: 0102030405
Version: 255 (0xFF) ID:   1 (0x01) type: DES3 length:  16 
Version: 255 (0xFF) ID:   2 (0x02) type: DES3 length:  16 
Version: 255 (0xFF) ID:   3 (0x03) type: DES3 length:  16 
Key version suggests factory keys
```

## N5

**Name**: NXP JCOP3 P60

## N6/N7

**Name**: NXP JCOP J3R280 P71 
**Card ATR**: `3B D5 18 FF 81 91 FE 1F C3 80 73 C8 21 10 0A`
**IDENTIFY response**: `010c0001a48400fe32aabdde5f7c0208000000000000000103184a335233353130323336333130343030dce5c19cfe6d0dcf05010007010108082e5ad88409c9bdb` -> J3R3510236310400

```
CPLC: ICFabricator=4790
      ICType=D321
      OperatingSystemID=4700
      OperatingSystemReleaseDate=0000 (2010-01-01)
      OperatingSystemReleaseLevel=0000
      ICFabricationDate=0136 (2010-05-16)
      ICSerialNumber=27339899
      ICBatchIdentifier=5382
      ICModuleFabricator=0000
      ICModulePackagingDate=0000 (2010-01-01)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (2010-01-01)
      ICPrePersonalizer=0C0E
      ICPrePersonalizationEquipmentDate=5937 (invalid date format)
      ICPrePersonalizationEquipmentID=33333938
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.3
-> GP Version: 2.3
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.3.112
-> GP SCP03 i=70
Tag 65: 1.2.840.114283.5.7.2.0.0
Tag 66: 1.3.6.1.4.1.42.2.110.1.3
-> JavaCard v3
Card Capabilities: 
Supports: SCP03 i=00 i=10 i=20 i=60 i=70 with AES-128 AES-196 AES-256
Supported DOM privileges: SecurityDomain, DelegatedManagement, CardReset, MandatedDAPVerification, TrustedPath, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration, CipheredLoadFileDataBlock
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, FinalApplication, GlobalService
Supported LFDB hash: 02
Supported Token Verification ciphers: 7B
Supported Receipt Generation ciphers: 0C
Supported DAP Verification ciphers: 7B
Version:  49 (0x31) ID:   1 (0x01) type: AES  length:  16 (AES-128)
Version:  49 (0x31) ID:   2 (0x02) type: AES  length:  16 (AES-128)
Version:  49 (0x31) ID:   3 (0x03) type: AES  length:  16 (AES-128)
```


## N8 

**Name**: NXP J2E
**Card ATR**: `3B F9 13 00 00 81 31 FE 45 4A 43 4F 50 32 34 32 52 33 A2`

```
CPLC: ICFabricator=4790
      ICType=5167
      OperatingSystemID=4791
      OperatingSystemReleaseDate=2348 (2012-12-13)
      OperatingSystemReleaseLevel=4000
      ICFabricationDate=6007 (2016-01-07)
      ICSerialNumber=00148398
      ICBatchIdentifier=1963
      ICModuleFabricator=4812
      ICModulePackagingDate=6014 (2016-01-14)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (2010-01-01)
      ICPrePersonalizer=0127
      ICPrePersonalizationEquipmentDate=1530 (invalid date format)
      ICPrePersonalizationEquipmentID=31343833
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.2
-> GP Version: 2.2
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.2.85
-> GP SCP02 i=55
Tag 65: 1.3.656.840.100.2.1.3
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
Card Capabilities: 
Version: 255 (0xFF) ID:   1 (0x01) type: DES3 length:  16 
Version: 255 (0xFF) ID:   2 (0x02) type: DES3 length:  16 
Version: 255 (0xFF) ID:   3 (0x03) type: DES3 length:  16 
Key version suggests factory keys
```


## N9

**Name**: NXP JCOP31 v2.4.1 72k
**Card ATR**: `3B F8 13 00 00 81 31 FE 45 4A 43 4F 50 76 32 34 31 B7`

```
CPLC: ICFabricator=4790
      ICType=5040
      OperatingSystemID=4791
      OperatingSystemReleaseDate=8102 (2018-04-12)
      OperatingSystemReleaseLevel=3100
      ICFabricationDate=1035 (2011-02-04)
      ICSerialNumber=00216995
      ICBatchIdentifier=4830
      ICModuleFabricator=0000
      ICModulePackagingDate=0000 (2010-01-01)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (2010-01-01)
      ICPrePersonalizer=0721
      ICPrePersonalizationEquipmentDate=2630 (invalid date format)
      ICPrePersonalizationEquipmentID=32313639
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.2.21
-> GP SCP02 i=15
Tag 65: 1.3.656.840.100.2.1.3
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
Card Capabilities: 
Version: 255 (0xFF) ID:   1 (0x01) type: DES3 length:  16 
Version: 255 (0xFF) ID:   2 (0x02) type: DES3 length:  16 
Version: 255 (0xFF) ID:   3 (0x03) type: DES3 length:  16 
Key version suggests factory keys
```

## N10

**Name**: NXP J3H145 JCOP3 SECID P60
**Card ATR**: `3B 94 95 81 01 46 54 56 01 C4`

```
CPLC: ICFabricator=4790
      ICType=0503
      OperatingSystemID=8211
      OperatingSystemReleaseDate=6351 (2016-12-16)
      OperatingSystemReleaseLevel=0302
      ICFabricationDate=8359 (2018-12-25)
      ICSerialNumber=01891207
      ICBatchIdentifier=4673
      ICModuleFabricator=4E30
      ICModulePackagingDate=5038 (2015-02-07)
      ICCManufacturer=3532
      ICEmbeddingDate=4246 (2014-09-03)
      ICPrePersonalizer=4A31
      ICPrePersonalizationEquipmentDate=3031 (2013-01-31)
      ICPrePersonalizationEquipmentID=38393132
      ICPersonalizer=0600
      ICPersonalizationDate=0123 (2010-05-03)
      ICPersonalizationEquipmentID=B148EF84

IIN: 420100
CIN: 45080000000000000000
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.2.85
-> GP SCP02 i=55
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
Card Capabilities: 
Supports: SCP02 i=55
Supports: SCP03 i=00 i=10 with AES-128 AES-196 AES-256
Supported DOM privileges: SecurityDomain, CardLock, CardTerminate, CardReset, CVMManagement, TrustedPath, AuthorizedManagement, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, FinalApplication, GlobalService
Supported LFDB hash: 02
Supported Token Verification ciphers: 01020840
Supported Receipt Generation ciphers: 0408
Supported DAP Verification ciphers: 01020840
Supported ECC Key Parameters: 0102030405
Version: 255 (0xFF) ID:   1 (0x01) type: DES3 length:  16 
Version: 255 (0xFF) ID:   2 (0x02) type: DES3 length:  16 
Version: 255 (0xFF) ID:   3 (0x03) type: DES3 length:  16 
Key version suggests factory keys
```

# Feitian

## F1

**Name**: Javacos A22 CR
**Card ATR**: `3B 9C 95 80 81 1F 03 90 67 46 4A 01 00 54 04 F2 72 FE 00 C0`

```
CPLC: ICFabricator=4090
      ICType=7892
      OperatingSystemID=86AA
      OperatingSystemReleaseDate=7068 (2027-03-09)
      OperatingSystemReleaseLevel=0154
      ICFabricationDate=9191 (2019-07-10)
      ICSerialNumber=09011064
      ICBatchIdentifier=0552
      ICModuleFabricator=4090
      ICModulePackagingDate=9191 (2019-07-10)
      ICCManufacturer=86AA
      ICEmbeddingDate=9191 (2019-07-10)
      ICPrePersonalizer=86AA
      ICPrePersonalizationEquipmentDate=9191 (2019-07-10)
      ICPrePersonalizationEquipmentID=00000000
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (invalid date format)
      ICPersonalizationEquipmentID=00000000

KDD: CF0A00007068090110640552
SSC: C102000E
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
Tag 6: 1.2.840.114283.4.2.85
-> GP SCP02 (i=55)
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
```

## F2

**Name**: Javacos JC30M48 CR
**Card ATR**: `3B 90 95 80 11 FE 6A`

No proper CPLC reply.
```
KDD: CF0A00000000000000000000
SSC: C1020019
Card Data:
```

# Athena

## A1

**Name**: Athena IDProtect
**Card ATR**: `3B D5 18 FF 81 91 FE 1F C3 80 73 C8 21 13 09`

```
CPLC: ICFabricator=4180
      ICType=010B
      OperatingSystemID=8211
      OperatingSystemReleaseDate=0352 (2010-12-18)
      OperatingSystemReleaseLevel=0005
      ICFabricationDate=3831 (invalid date format)
      ICSerialNumber=00062C2B
      ICBatchIdentifier=484A
      ICModuleFabricator=0000
      ICModulePackagingDate=0000 (2010-01-01)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (2010-01-01)
      ICPrePersonalizer=0000
      ICPrePersonalizationEquipmentDate=0000 (2010-01-01)
      ICPrePersonalizationEquipmentID=00000000
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

IIN: 420100
CIN: 45080000000000000000
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.1.5
-> GP SCP01 i=05
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
Card Capabilities: 
Version: 255 (0xFF) ID:   1 (0x01) type: DES3 length:  16 
Version: 255 (0xFF) ID:   2 (0x02) type: DES3 length:  16 
Version: 255 (0xFF) ID:   3 (0x03) type: DES3 length:  16 
Key version suggests factory keys
```

# G&D

## G1

**Name**: G&D Smartcafe 7.0
**Card ATR**: `3B F9 96 00 00 81 31 FE 45 53 43 45 37 20 0E 00 20 20 28`

```
CPLC: ICFabricator=0005
      ICType=0056
      OperatingSystemID=D001
      OperatingSystemReleaseDate=4212 (2014-07-31)
      OperatingSystemReleaseLevel=0102
      ICFabricationDate=059C (invalid date format)
      ICSerialNumber=0034002D
      ICBatchIdentifier=4D0F
      ICModuleFabricator=0000
      ICModulePackagingDate=0000 (2010-01-01)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (2010-01-01)
      ICPrePersonalizer=0000
      ICPrePersonalizationEquipmentDate=0000 (2010-01-01)
      ICPrePersonalizationEquipmentID=00000000
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.2.1
-> GP Version: 2.2.1
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.3.16
-> GP SCP03 i=10
Tag 65: 1.3.656.840.100.2.1.3
Tag 66: 1.3.6.1.4.1.42.2.110.1.3
-> JavaCard v3
Card Capabilities: 
Supports: SCP03 i=00 i=10 i=20 i=30 i=60 i=70 with AES-128 AES-196 AES-256
Supports: SCP02 i=15 i=55
Supported DOM privileges: SecurityDomain, DelegatedManagement, CardLock, CardTerminate, CardReset, CVMManagement, MandatedDAPVerification, TrustedPath, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, GlobalDelete, GlobalRegistry, FinalApplication
Supported LFDB hash: 02
Supported Token Verification ciphers: FF02
Supported Receipt Generation ciphers: FF02
Supported DAP Verification ciphers: FF02
Version: 255 (0xFF) ID:   1 (0x01) type: AES  length:  16 (AES-128)
Version: 255 (0xFF) ID:   2 (0x02) type: AES  length:  16 (AES-128)
Version: 255 (0xFF) ID:   3 (0x03) type: AES  length:  16 (AES-128)
Key version suggests factory keys
```

## G2

**Name**: G&D Smartcafe 6.0
**Card ATR**: `3B FE 18 00 00 80 31 FE 45 53 43 45 36 30 2D 43 44 30 38 31 2D 6E 46 A9`

```
CPLC: ICFabricator=4790
      ICType=5037
      OperatingSystemID=1671
      OperatingSystemReleaseDate=1146 (2021-05-26)
      OperatingSystemReleaseLevel=4003
      ICFabricationDate=5024 (2025-01-24)
      ICSerialNumber=970069A3
      ICBatchIdentifier=7271
      ICModuleFabricator=4792
      ICModulePackagingDate=0144 (2020-05-23)
      ICCManufacturer=1673
      ICEmbeddingDate=0283 (2020-10-09)
      ICPrePersonalizer=1674
      ICPrePersonalizationEquipmentDate=5092 (2015-04-02)
      ICPrePersonalizationEquipmentID=00000A01
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (invalid date format)
      ICPersonalizationEquipmentID=00000000

KDD: CF0A00005024970069A37271
SSC: C1020000
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
Tag 6: 1.2.840.114283.4.3.0
-> GP SCP03
Tag 66: 1.3.6.1.4.1.42.2.110.1.2
-> JavaCard v2
Card Capabilities: 
Version:   1 (0x01) ID:   1 (0x01) type: DES3         length:  16
Version:   1 (0x01) ID:   2 (0x02) type: DES3         length:  16
Version:   1 (0x01) ID:   3 (0x03) type: DES3         length:  16
```

# Infineon

## I1

**Name**: SECORA ID S, SLJ52GDT120CS
**Card ATR**: `3B B8 96 00 C0 08 31 FE 45 FF FF 11 54 30 50 23 00 6A`

```
CPLC: ICFabricator=4090
      ICType=1912
      OperatingSystemID=4090
      OperatingSystemReleaseDate=9078 (2019-03-19)
      OperatingSystemReleaseLevel=0100
      ICFabricationDate=7287 (2017-10-14)
      ICSerialNumber=A7178551
      ICBatchIdentifier=A065
      ICModuleFabricator=0000
      ICModulePackagingDate=0000 (2010-01-01)
      ICCManufacturer=0000
      ICEmbeddingDate=0000 (2010-01-01)
      ICPrePersonalizer=0000
      ICPrePersonalizationEquipmentDate=0000 (2010-01-01)
      ICPrePersonalizationEquipmentID=00000000
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

IIN: 4206000000000000
CIN: 45080000000000000000
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.2
-> GP Version: 2.2
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.3.16
-> GP SCP03 i=10
Tag 65: 1.2.840.114283.5.5
Tag 66: 1.3.6.1.4.1.42.2.110.1.3
-> JavaCard v3
Card Capabilities: 
Supports: SCP03 i=00 i=10 with AES-128 AES-196 AES-256
Supports: SCP02 i=15 i=55
Supported DOM privileges: SecurityDomain, DelegatedManagement, CardLock, CardTerminate, CardReset, CVMManagement, MandatedDAPVerification, TrustedPath, GlobalLock, GlobalRegistry, FinalApplication
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, TrustedPath, GlobalRegistry, FinalApplication
Supported LFDB hash: 02
Supported Token Verification ciphers: 03
Supported Receipt Generation ciphers: 3C
Supported DAP Verification ciphers: 03
Version: 255 (0xFF) ID:   1 (0x01) type: AES  length:  32 (AES-256)
Version: 255 (0xFF) ID:   2 (0x02) type: AES  length:  32 (AES-256)
Version: 255 (0xFF) ID:   3 (0x03) type: AES  length:  32 (AES-256)
Key version suggests factory keys
```

## I2

**Name**: CJTOP80K INF SLJ 52GLA080AL M84
**Card ATR**: `3B FE 18 00 00 80 31 FE 45 80 31 80 66 40 90 A5 10 2E 10 83 01 90 00 F2`

```
CPLC: ICFabricator=4090
      ICType=7165
      OperatingSystemID=544C
      OperatingSystemReleaseDate=2151 (2012-05-30)
      OperatingSystemReleaseLevel=2E10
      ICFabricationDate=2001 (2012-01-01)
      ICSerialNumber=00020724
      ICBatchIdentifier=4FC2
      ICModuleFabricator=4092
      ICModulePackagingDate=2339 (2012-12-04)
      ICCManufacturer=4093
      ICEmbeddingDate=2339 (2012-12-04)
      ICPrePersonalizer=0000
      ICPrePersonalizationEquipmentDate=0000 (2010-01-01)
      ICPrePersonalizationEquipmentID=00000000
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (2010-01-01)
      ICPersonalizationEquipmentID=00000000

IIN: 420100
CIN: 45080000000000000000
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.2
-> GP Version: 2.2
Tag 63: 1.2.840.114283.3
Tag 64: 1.2.840.114283.4.2.85
-> GP SCP02 i=55
Tag 65: 1.2.840.114283.5.5
Tag 66: 1.3.6.1.4.1.42.2.110.1.3
-> JavaCard v3
Card Capabilities: 
Supports: SCP02 i=55
Supported DOM privileges: SecurityDomain, DelegatedManagement, CardLock, CardTerminate, CardReset, CVMManagement, MandatedDAPVerification, TrustedPath, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication
Supported APP privileges: CardLock, CardTerminate, CardReset, CVMManagement, TrustedPath, GlobalRegistry, FinalApplication
Supported LFDB hash: 02
Supported Token Verification ciphers: 49
Supported Receipt Generation ciphers: 08
Supported DAP Verification ciphers: 49
Version: 255 (0xFF) ID:   1 (0x01) type: DES3 length:  16 
Version: 255 (0xFF) ID:   2 (0x02) type: DES3 length:  16 
Version: 255 (0xFF) ID:   3 (0x03) type: DES3 length:  16 
Key version suggests factory keys
```

# TaiSYS

## S1/S2

**Name**: TAiSYS SIMoME VAULT
**Card ATR**: `3B 9F 95 80 3F C7 A0 80 31 E0 73 FA 21 10 63 00 00 00 83 F0 90 00 BB`

```
CPLC: ICFabricator=FFFF
      ICType=FFFF
      OperatingSystemID=FFFF
      OperatingSystemReleaseDate=FFFF (invalid date format)
      OperatingSystemReleaseLevel=FFFF
      ICFabricationDate=6194 (2016-07-12)
      ICSerialNumber=EA7F2188
      ICBatchIdentifier=665D
      ICModuleFabricator=FFFF
      ICModulePackagingDate=FFFF (invalid date format)
      ICCManufacturer=FFFF
      ICEmbeddingDate=FFFF (invalid date format)
      ICPrePersonalizer=FFFF
      ICPrePersonalizationEquipmentDate=FFFF (invalid date format)
      ICPrePersonalizationEquipmentID=FFFFFFFF
      ICPersonalizer=FFFF
      ICPersonalizationDate=FFFF (invalid date format)
      ICPersonalizationEquipmentID=FFFFFFFF

IIN: 42074953445F49494E
CIN: 45074953445F43494E
KDD: CF0A112233445566778899AA
SSC: C10200E9
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.2
-> GP Version: 2.2
Tag 63: 1.2.840.114283.3
-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
Tag 6: 1.2.840.114283.4.2.85
-> GP SCP02 (i=55)
Tag 66: 1.3.6.1.4.1.42.2.110.1.16
Card Capabilities: 
```


# ACS

## C1

**Name**: ACS ACOSJ 40k
**Card ATR**: `3B 89 80 01 41 43 4F 53 4A 76 32 30 34 1C`

```
KDD: CF0A00000265018303953662
SSC: C1020005
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.2.1
-> GP Version: 2.2.1
Tag 63: 1.2.840.114283.3
-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
Tag 6: 1.2.840.114283.4.2.85
-> GP SCP02 (i=55)
Tag 66: 1.3.6.1.4.1.42.2.110.1.3
-> JavaCard v3
Card Capabilities: 
Version:  32 (0x20) ID:   1 (0x01) type: DES3         length:  16
Version:  32 (0x20) ID:   2 (0x02) type: DES3         length:  16
Version:  32 (0x20) ID:   3 (0x03) type: DES3         length:  16
```

# Gemalto

## E1

**Name**: Gemalto IDClassic 230
**Card ATR**: `3B 95 95 40 FF AE 01 03 00 00`

```
CPLC: ICFabricator=4090
      ICType=6145
      OperatingSystemID=2041
      OperatingSystemReleaseDate=4275 (2024-10-01)
      OperatingSystemReleaseLevel=0103
      ICFabricationDate=4043 (2024-02-12)
      ICSerialNumber=24162B41
      ICBatchIdentifier=52D4
      ICModuleFabricator=1942
      ICModulePackagingDate=4297 (2024-10-23)
      ICCManufacturer=2003
      ICEmbeddingDate=4312 (2024-11-07)
      ICPrePersonalizer=2004
      ICPrePersonalizationEquipmentDate=4312 (2024-11-07)
      ICPrePersonalizationEquipmentID=00010044
      ICPersonalizer=FFFF
      ICPersonalizationDate=FFFF (invalid date format)
      ICPersonalizationEquipmentID=FFFFFFFF

[WARN] GPData - GET DATA(IIN) not supported
[WARN] GPData - GET DATA(CIN) not supported
[WARN] GPData - GET DATA(KDD) not supported
[WARN] GPData - GET DATA(SSC) not supported
Card Data: 
[WARN] GPData - GET DATA(Card Data) not supported
Card Capabilities: 
[WARN] GPData - GET DATA(Card Capabilities) not supported
[WARN] GPData - GET DATA(Key Info Template) not supported
```

## E2
**Name**: Gemalto IDClassic 230
**Card ATR**: 3B 95 95 40 FF AE 01 03 00 00

```
CPLC: ICFabricator=4090
      ICType=6145
      OperatingSystemID=2041
      OperatingSystemReleaseDate=4275 (2024-10-01)
      OperatingSystemReleaseLevel=0103
      ICFabricationDate=1071 (2021-03-12)
      ICSerialNumber=2103362C
      ICBatchIdentifier=6311
      ICModuleFabricator=1942
      ICModulePackagingDate=2023 (2022-01-23)
      ICCManufacturer=1943
      ICEmbeddingDate=2023 (2022-01-23)
      ICPrePersonalizer=1944
      ICPrePersonalizationEquipmentDate=2023 (2022-01-23)
      ICPrePersonalizationEquipmentID=0000BA01
      ICPersonalizer=FFFF
      ICPersonalizationDate=FFFF (invalid date format)
      ICPersonalizationEquipmentID=FFFFFFFF

IIN: 4206FFFFFFFFFFFF
CIN: 4508FFFFFFFFFFFFFFFF
[WARN] GPData - GET DATA(KDD) not supported
[WARN] GPData - GET DATA(SSC) not supported
Card Data: 
[WARN] GPData - GET DATA(Card Data) not supported
Card Capabilities: 
[WARN] GPData - GET DATA(Card Capabilities) not supported
[WARN] GPData - GET DATA(Key Info Template) not supported
```

# Oberthur

## O1 

**Name**: Oberthur ID-One Cosmo 64
**Card ATR**: `3B 7B 18 00 00 00 31 C0 64 77 E9 10 00 01 90 00`

```
CPLC: ICFabricator=2050
      ICType=5000
      OperatingSystemID=4041
      OperatingSystemReleaseDate=5273 (2015-09-30)
      OperatingSystemReleaseLevel=0060
      ICFabricationDate=7031 (2027-01-31)
      ICSerialNumber=3091D362
      ICBatchIdentifier=0000
      ICModuleFabricator=1912
      ICModulePackagingDate=7031 (2027-01-31)
      ICCManufacturer=1913
      ICEmbeddingDate=7031 (2027-01-31)
      ICPrePersonalizer=1914
      ICPrePersonalizationEquipmentDate=7031 (2027-01-31)
      ICPrePersonalizationEquipmentID=00115221
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (invalid date format)
      ICPersonalizationEquipmentID=00000000

Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
Tag 6: 1.2.840.114283.4.1.5
-> GP SCP01 (i=05)
Card Capabilities: 
Version: 255 (0xFF) ID:   1 (0x01) type: DES3_RESERVED length:  16 (factory key)
```

## O2

**Name**: Oberthur Cosmo Dual 72
**Card ATR**: `3B 7B 18 00 00 00 31 C0 64 77 E3 03 00 82 90 00`

```
CPLC: ICFabricator=2050
      ICType=5000
      OperatingSystemID=4041
      OperatingSystemReleaseDate=4091 (2024-03-31)
      OperatingSystemReleaseLevel=005F
      ICFabricationDate=7157 (2017-06-06)
      ICSerialNumber=000002E7
      ICBatchIdentifier=0000
      ICModuleFabricator=1912
      ICModulePackagingDate=7157 (2017-06-06)
      ICCManufacturer=1913
      ICEmbeddingDate=7157 (2017-06-06)
      ICPrePersonalizer=0000
      ICPrePersonalizationEquipmentDate=0000 (invalid date format)
      ICPrePersonalizationEquipmentID=00000000
      ICPersonalizer=0000
      ICPersonalizationDate=0000 (invalid date format)
      ICPersonalizationEquipmentID=00000000

SSC: C1020000
Card Data: 
Tag 6: 1.2.840.114283.1
-> Global Platform card
Tag 60: 1.2.840.114283.2.2.1.1
-> GP Version: 2.1.1
Tag 63: 1.2.840.114283.3
-> GP card is uniquely identified by the Issuer Identification Number (IIN) and Card Image Number (CIN)
Tag 6: 1.2.840.114283.4.1.5
-> GP SCP01 (i=05)
Card Capabilities: 
Version: 255 (0xFF) ID:   1 (0x01) type: DES3         length:  16 (factory key)
```
