# netcost

## How to use

```
docker run --rm --privileged --net=host -ti docker.io/kinvolk/netcost netcost -ifindex 3 -netlist 192.168.0.0/16,127.0.0.0/8,10.0.0.0/8,0.0.0.0/0 -pretty
{
    "timestamp": "2020-08-07T17:05:36+02:00",
    "networks": {
        "0.0.0.0/0": {
            "ingressBytes": 1756,
            "egressBytes": 2097
        },
        "10.0.0.0/8": {
            "ingressBytes": 0,
            "egressBytes": 0
        },
        "127.0.0.0/8": {
            "ingressBytes": 0,
            "egressBytes": 0
        },
        "192.168.0.0/16": {
            "ingressBytes": 0,
            "egressBytes": 0
        }
    }
}
```
