This is provided for users to try out [bcc](https://github.com/iovisor/bcc) and kernel trace tools in container.

First, you need to run:
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

Now, from the container shell, you can try the [kernel-trace](https://github.com/alvenwong/kernel_trace) tools.
For example:
```bash
python in_probe.py -h
```

Please refer to the [bcc tutorial](https://github.com/iovisor/bcc/tree/master/docs/tutorial.md#1-general-performance).
