ECTester
========

Tests support and behavior of smartcards with JavaCard platform with focus on Eliptic curves (TYPE_EC_FP and TYPE_EC_F2M).

Usage
------
1. Upload simpleECC.cap using your favorite tool (e.g., [GlobalPlatformPro tool](https://github.com/martinpaljak/GlobalPlatform))
2. Run java -jar SimpleAPDU.jar
3. Inspect output log with annotated results

Following operations are tested:
- Allocation of new KeyPair class for specified parameters
- Generation of keypair with default curve 
- Setting of custom curve and keypair generation
- Generation of shared secret via ECDH
- Behavior of card when invalid curves/points are provided (shoudl fail)

Example output
--------------

    EC type:                                            ALG_EC_FP
    EC key length (bits):                               224 bits
      KeyPair object allocation:                        OK	  (0x9000)
      Generate key with def curve (fails if no def):    fail  (ILLEGAL_VALUE,	0x1)
      Set valid custom curve:                           OK	  (0x9000)
      Generate key with valid curve:                    OK	  (0x9000)
    !!ECDH agreement with valid point:                  fail  (0x6f00)
      ECDH agreement with invalid point (fail is good): fail  (unknown,	0x6f00)
      Set invalid custom curve (fail is good):          fail  (ILLEGAL_VALUE,	0x1)
      Generate key with invalid curve (fail is good):   fail  (skipped,	0xee1)


*Explanation: ALG_EC_FP with 224b curve was tested. Is supported by card (KeyPair object allocation: OK), don't have preset default curve (Generate key with def curve: fail), custom curve can be set (Set valid custom curve: OK), new keypair can be generated (Generate key with valid curve: OK), ECDH key agreement failed to execute (ECDH agreement with valid point: fail) altough it was supposed to suceed (log line is therefore marked with !!), ECDH wil fail (expected behavior) if invalid point is provided (ECDH agreement with invalid point: fail), invalid custom curve cannot be set (expected behavior) (Set invalid custom curve: fail) and new keypair cannot be generated with invalid curve (Generate key with invalid curve: skipped) - last test was skipped as invalid curve canot be set.*


If you are interested in testing support for other JavaCard algorithms, please visit JCAlgTester project: https://github.com/crocs-muni/JCAlgTest

