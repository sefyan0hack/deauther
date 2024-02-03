chann=1

while true; do
    if [ $chann -le 13 ]; then
	echo $chann
        iwconfig wlan1mon channel $chann
        ((chann++))
        sleep .5
    else
        chann=1
    fi
done
