ECTester
========

Tests support and behavior of smartcards with JavaCard platform with focus on Eliptic curves (TYPE_EC_FP and TYPE_EC_F2M).

Usage
------
1. Upload simpleECC.cap using your favorite tool (e.g., [GlobalPlatformPro tool](https://github.com/martinpaljak/GlobalPlatform))
2. Run `java -jar SimpleAPDU.jar`
3. Inspect output log with annotated results

Following operations are tested:
- Allocation of new KeyPair class for specified parameters
- Generation of keypair with default curve 
- Setting of custom curve and keypair generation
- Generation of shared secret via ECDH
- Signature via ECDSA
- Behavior of card when invalid curves/points are provided (should fail)

See `java -jar SimpleAPDU.jar -h` for more. 

Example output
--------------

    ### Test for support and with valid and invalid EC curves
    EC type:                                             ALG_EC_FP
    EC key length (bits):                                256 bits
       KeyPair object allocation:                           OK	(0x9000)
       Generate key with def curve (fails if no def):       OK	(0x9000)
       Set valid custom curve:                              OK	(0x9000)
       Generate key with valid curve:                       OK	(0x9000)
    !! ECDH agreement with valid point:                     fail	(unknown,	0x6f00)
       ECDH agreement with invalid point (fail is good):    fail	(ILLEGAL_VALUE,	0x   1)
       ECDSA signature on random data:                      OK	(0x9000)
       Set anomalous custom curve (may fail):               OK	(0x9000)
       Generate key with anomalous curve (may fail):        fail	(unknown,	0x6f00)
       ECDH agreement with small order point (fail is good):fail	(skipped,	0x ee1)
       Set invalid custom curve (may fail):                 OK	(0x9000)
       Generate key with invalid curve (fail is good):      fail	(unknown,	0x6f00)
       Set invalid field (may fail):                        OK	(0x9000)
       Generate key with invalid field (fail si good):      fail	(unknown,	0x6f00)
   
*Explanation: ALG_EC_FP with 256b curve was tested. Is supported by card (KeyPair object allocation: OK), don't have preset default curve (Generate key with def curve: fail), custom curve can be set (Set valid custom curve: OK), new keypair can be generated (Generate key with valid curve: OK), ECDH key agreement failed to execute (ECDH agreement with valid point: fail) although it was supposed to succeed (log line is therefore marked with !!), ECDH wil fail (expected behavior) if invalid point is provided (ECDH agreement with invalid point: fail), ECDSA signature worked and verified correctly (ECDSA signature on random data: OK), anomalous curve can be set (Set anomalous custom curve: OK), however generating a key on it will fail (Generate key with anomalous curve: fail), ECDH with small-order public key provided will fail as intended (ECDH agreement with small order point: fail), invalid custom curve could be set (Set invalid custom curve: OK), new keypair cannot be generated with invalid curve (Generate key with invalid curve: fail), invalid field (non-prime) could be set (Set invalid field: OK), however a key could not be generated (Generate key with invalid field: fail).*


If you are interested in testing support for other JavaCard algorithms, please visit JCAlgTester project: https://github.com/crocs-muni/JCAlgTest

