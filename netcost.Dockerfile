FROM golang:latest
LABEL maintainer="Alban Crequy <alban@kinvolk.io>"

ADD netcost /bin/
CMD ["/bin/netcost", "-ifindex", "3", "-netlist", "192.168.0.0/16,0.0.0.0/0"]
