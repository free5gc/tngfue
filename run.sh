#!/usr/bin/env bash

sudo -v
if [ $? == 1 ]
then
    echo "[ERRO][TNGFUE] Without root permission, you cannot run TNGFUE"
    exit 1
fi

PID_LIST=()
IFACE_NAME='' # to store the network interface name used to connect to the TNGF / Wi-Fi AP
IFACE_IP='192.168.1.202' # IP address to be used by the network interface
IFACE_MASK='24' # network mask to be used by configuration command
IFACE_BROADCAST_IP='192.168.1.255' # IP address to be used by configuration command
ENABLE_DEBUG=0 # controls if debug messages are enabled

case $1 in # insert a 'case statement' to allow adding other input parameters in the future
    # TODO delete the comment above whenever a new parameter is added
    -debug)
    ENABLE_DEBUG=1
    ;;
esac

function terminate()
{
    echo "[INFO][TNGFUE] Terminating TNGFUE..."
    sudo kill -SIGTERM ${PID_LIST[@]}
    sleep 3 # gives enough time for wpa_supplicant to finish when it's stuck or in a loop

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
}

# If IFACE_NAME is empty, read the Wi-Fi interface name from sec.conf
if [[ -z $IFACE_NAME ]]; then
    IFACE_NAME="$(head -n 1 ./wpa_supplicant/sec.conf | cut -d : -f 2)" # get the second slice (colon separated) of the first line of the file
else
    echo "[INFO][TNGFUE] Interface already set. Using $IFACE_NAME as interface name"
fi

# Configure IP and route
sudo ip addr add $IFACE_IP/$IFACE_MASK brd $IFACE_BROADCAST_IP dev $IFACE_NAME
sudo ip route add default via $IFACE_IP dev $IFACE_NAME

# Run TNGFUE
cd wpa_supplicant
if [[ $ENABLE_DEBUG -eq 0 ]]; then
    sudo ./wpa_supplicant -c ../wpa_supplicant.conf -i $IFACE_NAME &
elif [[ $ENABLE_DEBUG -eq 1 ]]; then
    sudo ./wpa_supplicant -c ../wpa_supplicant.conf -i $IFACE_NAME -dd &
else
    echo "[ERRO][TNGFUE] Failed to set ENABLE_DEBUG variable"
    exit 2
fi
SUDO_TNGFUE_PID=$!
sleep 0.1
TNGFUE_PID=$(pgrep -P ${SUDO_TNGFUE_PID})
PID_LIST+=($SUDO_TNGFUE_PID $TNGFUE_PID)
if [[ $ENABLE_DEBUG -eq 1 ]]; then echo "[DEBU][TNGFUE]" SUDO_TNGFUE_PID $SUDO_TNGFUE_PID; echo "[DEBU][TNGFUE]" TNGFUE_PID $TNGFUE_PID; fi

trap terminate SIGINT
wait ${PID_LIST}
echo "[INFO][TNGFUE] The TNGFUE terminated successfully"
exit 0
