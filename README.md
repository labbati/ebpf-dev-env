To be run in the docker environement:

```
docker compose build
```

DO NOT STRACE `go run app.go`. Instead run `go build app.go` and then `./app`.
```
strace -f -e write=all -t ./app
```

If you want to play with BCC, after you are running the above application:

```
cd /opt/bcc/examples/networking/http_filter
python http-parse-complete.py
```

Then from _outside_ the container

```
curl localhost:9090/e
```
