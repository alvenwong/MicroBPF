# bcc-docker
[bcc-docker](https://hub.docker.com/r/zlim/bcc/) is provided for user to try out [bcc](https://github.com/iovisor/bcc).

First, you need to run:
```bash
sudo docker build -t bcc-example .
```

From your host shell:
```bash
sudo docker run -it --rm \
  --privileged \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/localtime:/etc/localtime:ro \
  bcc-example
```

Now, from the container shell, you can try the [kernel-trace](https://github.com/alvenwong/kernel_trace) tools in probes/.
For example;
```bash
python in_probe.py
```

Please refer to the [bcc tutorial](https://github.com/iovisor/bcc/tree/master/docs/tutorial.md#1-general-performance).
