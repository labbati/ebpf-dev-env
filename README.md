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
    2. In another terminal, run the ebpf program: `python bcc/examples/networking/http_filter/http-parse-complete.py`
    3. From outside the container, run the following command `curl -v localhost:9090/e`

The output of the bcc window should be

```
GET /e HTTP/1.1
HTTP/1.1 200 OK
```