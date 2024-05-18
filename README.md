To be run in the docker environement:

```
docker build -t dev-image .
```


DO NOT STRACE `go run app.go`
```
strace -f -e write=all -t ./app
```
