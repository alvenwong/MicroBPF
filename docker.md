This is provided for users to try out [bcc](https://github.com/iovisor/bcc) and kernel trace tools in container.

First, you need to build the image:
```bash
sudo docker build -t bcc .
```

From your host shell:
```bash
sudo docker run -it --rm \
  --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/localtime:/etc/localtime:ro \
  -v /usr/local:/usr/local:consistent \
  bcc
```

You can also directly run the container without build using the following command:
```bash
sudo docker run -it --rm \
  --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/localtime:/etc/localtime:ro \
  -v /usr/local:/usr/local:consistent \
  dockerwangzhuang/bcc
```
Or
```bash
sh docker_run.sh
```

Now, from the container shell, you can try the [MicroBPF](https://github.com/alvenwong/MicroBPF) tools.
For example:
```bash
python in_probe.py -h
```
If you run the python files with "-o", i.e., redirecting the TCP metrics into specific files instead of stdout, you can check these files in /usr/local/bcc/ in the host in which the container is runing. Without "-o", the metrics will display directly on the terminal.
