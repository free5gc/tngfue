## Execution Flow

1. For a wireless connection, keep the device's Wi-Fi disconnected before you executing `./wpa_supplicant`
2. Use `./wpa_supplicant -h` to list all parameter usage
3. Some situations listed below
```shell!
// In wpa_supplicant sub-folder
// -c: configuration file
// -i: interface to listen
// -D: driver name
// -dd: show detail message
        
// 1. wireless connection
> sudo ./wpa_supplicant -c ../wpa_supplicant.conf -i <wifi interface name> -dd
        
// 2. wired conncetion
> sudo ./wpa_supplicant -c ../wpa_supplicant.conf -i <wired interface name> -D wired -dd
```

For detailed execution steps and TNGF usage, refer to [this guide](https://free5gc.org/guide/TNGF/tngfue-installation/)!