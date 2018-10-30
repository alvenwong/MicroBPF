#!/bash/sh

command=$1
server_pid=0

if [ "$command" = "start" ]; then
	cd nic
	rm -f trace/*
	python epoll_server.py &
	server_pid=$!
	echo $server_pid

elif [ "$command" = "kill" ]; then
	PIDS=$(ps -eaf)
	PID=$(echo "$PIDS" | grep "python epoll_server.py" | awk '{print $2}')
	if [ ! -z "$PID" ]; then
		echo $PID
		sudo kill -9 $PID
	fi

else
	echo "unknown command"
fi
