set moduleName=mem

HD-Adb -s emulator-5554 shell "su -c 'rm data/local/tmp/%moduleName%'"
HD-Adb -s emulator-5554 push libs/armeabi-v7a/%moduleName% data/local/tmp/%moduleName%
HD-Adb -s emulator-5554 shell "su -c 'chmod 7777 data/local/tmp/%moduleName%'"
HD-Adb -s emulator-5554 shell "su -c 'chown 0 data/local/tmp/%moduleName%'"
HD-Adb -s emulator-5554 shell "su -c 'chgrp 0 data/local/tmp/%moduleName%'"