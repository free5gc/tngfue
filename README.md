# Trusted Non-3GPP Gateway Function UE

## Execution Flow

TODO

## Additional Tips

1. For a wireless connection, keep the device's Wi-Fi interface disconnected before executing the UE
2. Use `./wpa_supplicant -h` to list all available parameters
3. Some useful wpa supplicant parameters:
- `-c`: set configuration file
- `-i`: interface to listen
- `-D`: set driver name to be used
- `-d`: show debug messages
- `-dd`: show even more detailed debug messages
4. Some usage examples:

**Note:** Run the commands below inside [wpa_supplicant](./wpa_supplicant/) sub-folder

- Wireless connection
```
sudo ./wpa_supplicant -c ../wpa_supplicant.conf -i <wifi interface name> -dd
```
- Wired conncetion (So far, this option has not been tested with TNGF)
```
sudo ./wpa_supplicant -c ../wpa_supplicant.conf -i <wired interface name> -D wired -dd
```

For detailed execution steps and TNGF usage, please, refer to [this guide](https://free5gc.org/guide/TNGF/tngfue-installation/)