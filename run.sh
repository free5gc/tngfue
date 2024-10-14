#!/usr/bin/env bash

sudo -v
if [ $? == 1 ]
then
    echo "[ERRO][TNGFUE] Without root permission, you cannot run TNGFUE"
    exit 1
fi

PID_LIST=()
IFACE_NAME='wlp3s0' # network interface used to connect to the TNGF / Wi-Fi AP
IFACE_IP='192.168.1.202' # IP address to be used by the network interface
IFACE_MASK='24' # Network mask to be used by configuration command
IFACE_BROADCAST_IP='192.168.1.255' # IP address to be used by configuration command

function terminate()
{
    # Remove all GRE interfaces
    echo "[INFO][TNGFUE] Removing all GRE interfaces"
    GREs=$(ip link show type gre | awk 'NR%2==1 {print $2}' | cut -d @ -f 1)
    for GRE in ${GREs}; do
        sudo ip link del ${GRE}
        echo del ${GRE}
    done

    # Prepare XFRM to terminate
    sudo ip xfrm policy flush
    sudo ip xfrm state flush

    # Remove all XFRM interfaces
    echo "[INFO][TNGFUE] Removing all XFRM interfaces"
    XFRMIs=$(ip link show type xfrm | awk 'NR%2==1 {print $2}' | cut -d @ -f 1)
    for XFRMI in ${XFRMIs}; do
        sudo ip link del ${XFRMI}
        echo del ${XFRMI}
    done

    # Remove IP and route
    echo "[INFO][TNGFUE] Removing IP and route"
    sudo ip addr flush $IFACE_NAME # removes IP and default route too

    echo "[INFO][TNGFUE] Terminating TNGFUE..."
    sudo kill -SIGTERM ${PID_LIST[@]}

    cd ..
}

# Configure IP and route
sudo ip addr add $IFACE_IP/$IFACE_MASK brd $IFACE_BROADCAST_IP dev $IFACE_NAME
sudo ip route add default via $IFACE_IP dev $IFACE_NAME

# Run TNGFUE
cd wpa_supplicant
sudo ./wpa_supplicant -c ../wpa_supplicant.conf -i $IFACE_NAME &
SUDO_TNGFUE_PID=$!
sleep 0.1
echo "[DEBUG][TNGFUE]" SUDO_TNGFUE_PID $SUDO_TNGFUE_PID
TNGFUE_PID=$(pgrep -P ${SUDO_TNGFUE_PID})
PID_LIST+=($SUDO_TNGFUE_PID $TNGFUE_PID)
echo "[DEBUG][TNGFUE]" TNGFUE_PID ${TNGFUE_PID}

trap terminate SIGINT
wait ${PID_LIST}
sleep 1
echo "[INFO][TNGFUE] The TNGFUE terminated successfully"
exit 0