# EAP 5G
wpa_supplicant modified version for EAP 5G
## TNGF Setting
- eap5g/wpa_supplicant.conf: ssid=```AP/openwrt ssid name```
- eap5g/src/eap_peer/eap_vendor_test.c: wifiifname=```UE wifi interface name```
- eap5g/wpa_supplicant/sec.conf: 
    - imsi_identity:```supi```
    - nai_username:type0.rid61695.schid0.userid```msin```
    - SQN: ```webconsole SQN - 1```

## Usage
- The whole package can be compiled in the sub-folder ```wpa_supplicant``` after change. Use ```make``` to compile the file and executable should be generated in the sub-folder.
- (Optional) If there is need to change the environment executable, use ```sudo make install```.
- The configuration files ```wpa_supplicant.conf``` should be setup with custom need. Parameter ```eap``` indicates the types supported in the connection, make sure ```VENDOR-TEST``` is presented.
    - For wireless connection, ap_scan is automatically on and the key management should be ```IEEE8021X```
        - For wired connection, ap_scan need to be switched off and the key management should be ```WPA-EAP```
        
## Execute Flow
1. For wireless connection, turn off wifi connection in the begining.
2. Some situations listed below.
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
3. For wireless connection, turn on wifi connection **after** the command executed.
## File changed
- ```src/eap_peer/eap_vendor_test.c```: The main extension for 5G data
- ```wpa_supplicant/.config```: Open the setting for ```VENDOR-TEST```
- ```wpa_supplicant/Makefile```: let the vendor type suppport key encryption
