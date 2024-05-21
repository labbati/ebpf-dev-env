To be run in the docker environement:

```
docker compose build
```

DO NOT STRACE `go run app.go`. Instead run `go build app.go` and then `./app`.
```
strace -f -e write=all -t ./app
```

If you want to play with BCC:

    1. In a terminal, run the app: `./app`
    2. In another terminal, run the ebpf program: `python bcc/examples/networking/http_filter/http-parse-complete.py -i lo` (or `... -i eth0`)
    3. In another terminal, run the following curl command `curl -v localhost:9090/e`
