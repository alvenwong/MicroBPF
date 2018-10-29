#!/bash/sh

command=$1
port=$2

kill_pid () {
	PIDS=$1
	function=$2

	PID=$(echo "$PIDS" | grep "$function" | awk '{print $2}')
	if [ ! -z "$PID" ]; then
		echo $PID
		sudo kill -9 $PID
	fi
	sudo_func="sudo ""$2"
	PID=$(echo "$PIDS" | grep "$sudo_func" | awk '{print $2}')
	if [ ! -z "$PID" ]; then
		echo $PID
		sudo kill -9 $PID
	fi
}


if [ "$command" = "start" ]; then
	sudo rm -f /usr/local/bcc/*
	cd nic
	sudo python client.py &
	cd ..
	sudo python tcpout.py -p $port -o &
	sudo python tcpin.py -p $port -o &
	sudo python tcpack.py -p $port -o &
	

elif [ "$command" = "kill" ]; then
	PIDS=$(ps -eaf)
	kill_pid "$PIDS" "python client.py"
	kill_pid "$PIDS" "python tcpout.py -p 80 -o"
	kill_pid "$PIDS" "python tcpin.py -p 80 -o"
	kill_pid "$PIDS" "python tcpack.py -p 80 -o"

else
	echo "unknown command"
fi
