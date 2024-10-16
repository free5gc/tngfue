#!/usr/bin/env bash

sudo -v
if [ $? == 1 ]
then
    echo "[ERRO][TNGFUE] Without root permission, you cannot install TNGFUE prerequisites"
    exit 1
fi

IFACE_NAME='wlp3s0' # network interface used to connect to the TNGF / Wi-Fi AP
# wpa_supplicant.conf vars
SSID="free5gc-ap"
IDENTITY="tngfue"
PASSWORD="free5gctngf"
# sec.conf vars
K_VAL="8baf473f2f8fd09487cccbd7097c6862"
IMSI="208930000000007"
MSIN=${IMSI: -10}
SQN="16f3b3f70fe1"
AMF_PORT="8000"
OPC="8e27b6af0e692e750f32667a3b14605d"

# Install prerequisites
echo "[INFO][TNGFUE] Installing prerequisites"
sudo apt update && sudo apt upgrade -y
sudo apt install -y git make gcc libssl-dev libdbus-1-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev

# Update supplicant config
echo "[INFO][TNGFUE] Updating wpa_supplicant.conf"
echo "ctrl_interface=udp
update_config=1
network={
    ssid=\"$SSID\"
    key_mgmt=WPA-EAP
    eap=VENDOR-TEST IKEV2
    identity=\"$IDENTITY\"
    password=\"$PASSWORD\"
}" > wpa_supplicant.conf


# Update sec config
cd wpa_supplicant
echo "[INFO][TNGFUE] Updating sec.conf"
echo "wifiifname:$IFACE_NAME
K:$K_VAL
imsi_identity:20893$MSIN
nai_username:type0.rid61695.schid0.userid$MSIN
SQN:$SQN
AMF:$AMF_PORT
OPC:$OPC" > sec.conf

echo "[INFO][TNGFUE] Building wpa_supplicant binary"
make
echo "[INFO][TNGFUE] Done"
