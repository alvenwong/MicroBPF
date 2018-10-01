sudo docker run -it --rm --privileged \
	 -v /lib/modules:/lib/modules:ro \
	 -v /usr/src:/usr/src:ro \
	 -v /etc/localtime:/etc/localtime:ro \
	 bcc-example
