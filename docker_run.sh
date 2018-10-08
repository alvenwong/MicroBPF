sudo docker run -it --rm --privileged \
	 -v /lib/modules:/lib/modules:ro \
	 -v /usr/src:/usr/src:ro \
	 -v /etc/localtime:/etc/localtime:ro \
	 -v /usr/local:/usr/local:consistent \
	 dockerwangzhuang/bcc
