# Trusted Non-3GPP Gateway Function UE

## Execution Flow

### 1. Clone the repository

```
git clone https://github.com/free5gc/tngfue.git
cd tngfue
```

### 2. Install prerequisites and UE configuration files

The [prepare.sh](./prepare.sh) script was designed to automate this process

```
./prepare.sh
```

**Tip:** To customize the script's execution flow, update the variables in the beginning of the file

**Note:** Make sure the parameters match the configuration both on free5gc database/webconsole and on Wi-Fi AP

### 3. Run TNGFUE

The [run.sh](./run.sh) script was designed to automate the processes required to run the UE (and to enable multiple UE executions)

```
./run.sh
```

**Note:** Make sure the parameters match the configuration on Wi-Fi AP and available network interface name

## Additional Tips

1. For a wireless connection, keep the device's Wi-Fi interface disconnected before executing the UE
2. Use `./wpa_supplicant -h` to list all available parameters
3. Some useful wpa supplicant parameters:
- `-c`: set configuration file
- `-i`: interface to listen
- `-D`: set driver name to be used
- `-d`: show debug messages
- `-dd`: show even more detailed debug messages
4. Debug messages can be enabled using `./run.sh -debug`
5. Some other usage examples:

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