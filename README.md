ECTester
=======

Tests support and behavior of smartcards with JavaCard platform with focus on Eliptic curves (TYPE_EC_FP and TYPE_EC_F2M).

Usage:

1. Upload simpleECC.cap using your favorite tool (e.g., GlobalPlatformPro tool https://github.com/martinpaljak/GlobalPlatform)
2. Run java -jar SimpleAPDU.jar
3. Inspect output log with annotated results

Following operations are tested:
- Allocation of new KeyPair class for specified parameters
- Generation of keypair with default curve 
- Setting of custom curve and keypair generation
- Generation of shared secret via ECDH
- Behavior of card when invalid curves/points are provided (shoudl fail)

If you are interested in testing support for other JavaCard algorithms, please visit: JCAlgTester project: https://github.com/crocs-muni/JCAlgTest
