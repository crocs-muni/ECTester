@ECHO OFF
SETLOCAL enabledelayedexpansion

SET n=0
:loop
IF NOT "%1"=="" (
    IF "%1"=="--dangerous" (
        SET dangerous=1
    ) ELSE (
        SET positional[!n!]=%1
        SET /A n+=1
    )
    SHIFT
    GOTO :loop
)

IF NOT "%n%"=="1" (
    ECHO "One argument expected:"
    ECHO "    ./ectester-reader.bat [--dangerous] CARD_NAME"
)

SET card=!positional[%%0]!

SET tests="default test-vectors"
java -jar ECTesterReader.jar -t default -a --format yaml -l %card%.default
java -jar ECTesterReader.jar -t test-vectors -a --format yaml -l %card%.test-vectors
IF "%dangerous%"=="1" (
    SET tests=%tests% "invalid wrong composite"
    java -jar ECTesterReader.jar -t invalid -a --format yaml -l %card%.invalid
    java -jar ECTesterReader.jar -t wrong -a --format yaml -l %card%.wrong
    java -jar ECTesterReader.jar -t composite -a --format yaml -l %card%.composite
)

zip %card%.zip %tests%
