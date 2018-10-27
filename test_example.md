# Introduce
We will use Apache and Redis containers to test our eBPF tools.

# Apache
## Run Apache server image
```bash
docker run -dit --name tecmint-web -p 80:80 -v /home/user/website/:/usr/local/apache2/htdocs/ httpd:2.4
```
## An example HTML file
```bash
vim /home/user/website/docker.html
```
```bash
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>A HTML file in Apache server</title>
</head>
<body>
    <h1>A test HTML file for Apache</h1>   
</body>
</html>
```
## Run Apache benchmark image
```bash
docker run --rm jordi/ab -k -c 10 -n 1000 http://x.x.x.x:8080/docker.html
```
x.x.x.x is the IP of the host (VM or PM) in which the benchmark container is running.

# Redis
We can run Redis server container and its benchmark container in two modes: intra-host mode and inter-host mode.
In intra-host mode, the two containers are running in the same host, while in inter-host mode, they are running in different hosts.

## Intra-host mode
### Run Redis server image
```bash 
docker run —name redis -d redis
```
### Run Redis benchmark image
```bash
docker run -it --rm --link redis:redis clue/redis-benchmark —n 10 -c 1
```

## Inter-host mode
### Run Redis server image
```bash 
docker run -p 6379:6379 —name redis -d redis
```
### Run Redis benchmark image
```bash
docker run -it --rm --link redis:redis clue/redis-benchmark -h x.x.x.x -p 6379 —n 10 -c 1
```
x.x.x.x is the IP of the host in which the Redis server container is running.

# Useful links
[Apache httpd](https://hub.docker.com/_/httpd/) <br>
[httpd-benchmark](https://hub.docker.com/r/jordi/ab/) <br>
[redis](https://hub.docker.com/_/redis/) <br>
[redis-benchmark](https://hub.docker.com/r/clue/redis-benchmark/)
