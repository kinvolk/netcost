// Code generated by go-bindata.
// sources:
// bpf/netcost-bpf.o
// DO NOT EDIT!

package netcostdata

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _netcostBpfO = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x9b\x7b\x90\x1c\xc5\x7d\xc7\xbf\xb3\xb3\x3b\xda\xbb\xd5\xce\xad\x74\xd2\xe9\x4e\x12\x62\x24\x90\xb8\x43\xa7\xbd\x3b\xe9\x72\x92\x11\x12\x27\xa1\xd7\x81\x80\x43\x08\x90\x78\x8d\x66\x77\x67\x6f\x97\x7d\x32\x33\x77\xe8\xc0\x09\x82\xb2\xe1\x92\x50\x0e\x50\x71\xc0\xb8\x9c\xc8\xe0\x10\x15\x71\x0c\xb6\x93\xc2\x45\x51\x81\x60\x27\xe0\x4a\x1c\x48\xd9\x31\x38\xc1\x0e\xe5\xc4\x2e\x39\x40\x2c\xe3\x97\x62\x70\x5d\xea\xd7\xd3\xb3\xd3\x37\xba\x46\xe4\xf1\x5f\xa6\xea\x76\xfa\xf3\xed\x5f\xbf\xbb\xa7\xa7\x7f\x23\xdd\xb5\x7b\xff\x9e\x98\xa2\x20\xb8\x14\xfc\x12\x21\x85\xd7\x89\xc1\x30\x3c\xca\x7f\x97\x41\xc1\xf3\x5d\xbe\xd6\x0b\x60\x21\x80\x6b\xb1\x1b\x48\x02\xcf\x28\x80\x01\x20\xbf\xfc\xf4\x2c\xc5\x3f\xff\xb8\x6f\xb7\x40\x05\xde\x9f\x9d\x9d\xb5\xac\x38\xe3\x6b\x95\x24\x28\xf4\xbc\xe5\xc7\x3f\x13\x03\x56\xd1\x3d\x0e\xa6\x7f\x1c\xc0\x72\x00\x13\xf0\xf3\x7b\x89\xdf\x6d\xb4\x61\x76\x76\x76\x36\x81\xcd\x2c\x9d\x98\x7e\xf9\x87\x48\xff\x0c\x6f\x64\x4d\x19\xf0\xd3\x29\x40\x3b\x80\xca\xf2\x93\xac\xbe\xdd\x0a\x30\x74\x91\x31\x46\xe1\xf1\x6d\x6b\x8f\xde\xb9\xfc\xcd\x96\x9e\x6b\x16\x4d\x0a\x37\x9d\xc6\xc4\x9d\xcb\x5f\x67\xba\xf5\xf8\xfb\x7e\x3b\x3f\xcb\xdb\xa9\x00\xaf\xcf\xce\xce\x52\x7d\x16\xf3\x7a\x68\x14\xff\x18\x8f\x8f\x01\xa7\x67\x67\x67\xbb\x23\x9d\xfd\x71\x36\x06\xd4\x8f\x8b\x5a\xf5\xa2\xcb\x5d\x7e\xaa\x55\x7e\xcd\x6a\x5e\x44\x61\x63\xed\xd1\xf6\x3b\x85\xfa\x36\x26\xeb\x05\xa6\x97\xeb\x86\x58\xdf\xb1\x71\xa3\x4e\xe1\x86\x67\x14\x3f\x4c\x7d\x7b\x84\xfa\x26\x90\x62\xf1\xe1\x78\x25\x58\xbf\x5a\xbc\xbf\xff\x39\x93\x6c\xd5\x53\x61\x9c\x61\xec\x5b\x89\x76\x88\xd8\x75\xfb\xcc\xdb\xfd\x49\x7e\xa7\xd2\x92\x7c\x8c\xc0\x6d\xa9\xbf\xa9\xaf\x69\x3c\x68\x2c\xda\x59\x8b\xa8\x35\xd4\x62\x6a\x2d\xf5\x08\xf5\x06\xf6\x8e\xef\x47\xbe\x6a\xd5\x27\x8c\x29\xdb\x71\xcb\x8d\xba\x31\x34\x98\x1d\xcc\x0e\x19\xbd\x7b\xec\x42\xc3\xb1\x38\x6e\xd8\x98\x2d\xe6\x37\x6d\xec\xa3\xac\x07\xea\xb6\x97\x6f\xb8\xde\x86\x5c\xb3\x98\xcd\x63\xa0\xd4\xa8\xd9\x03\x56\x35\x67\xd5\x07\x26\x1a\x03\xae\x93\x1f\x98\x28\x7b\xa5\xc9\x5c\x36\xdf\xa8\x0d\x54\xca\xf5\xa9\x46\xb5\x12\xa4\x41\xb5\x3a\x55\xcb\x52\xc2\x6a\xc3\x2a\x64\x4b\x56\xb5\x08\x0a\x99\x3c\x54\x9f\x30\xd8\xcf\x64\xdd\x2d\x4f\xd4\x6d\xaa\xab\x87\x6a\xb3\x66\xba\x9e\xe5\xb9\xf0\xa6\x9b\x36\xe6\xc4\x55\xec\x69\xd3\x2d\xdf\x61\x63\xca\xaa\x4e\xda\x7e\xb0\x66\x1d\x35\xed\xba\xe7\x94\x6d\x97\x86\xde\x2c\x56\xad\x09\x97\x75\x0a\x51\xc1\x2e\xc2\xac\x96\xf3\x76\xdd\xb5\x91\x2f\x59\x0e\x4c\x73\xc7\x81\x03\x3b\x0e\x9b\xd7\x8c\xdd\xb0\xdb\x3c\x78\x78\x7c\xb7\x69\x32\x6b\xb7\x92\x33\x59\xe5\x72\xd3\x9e\xed\x82\x8a\x33\xcd\xc9\x4d\x1b\x59\xa4\xe7\x58\x79\xdb\x6c\x3a\xe5\xba\x57\x69\xe5\x5d\x6d\x34\x2a\x93\x4d\xd3\xae\xda\xb5\x70\x10\x58\xfd\x2b\xf6\x34\x4c\xd3\x34\x8b\x35\x0f\x6e\x25\x87\xaa\x5d\x47\xb3\xe2\x99\xac\x45\x35\xcb\xa9\xe0\xb6\x49\x7b\xd2\xa6\x5c\x9a\xe5\xfa\x04\x2d\x15\xaf\x91\x6f\x54\x31\x55\xb5\xea\x66\xd3\xb1\x5d\xbb\xee\xf9\xe0\xe5\xcb\x81\xda\xf0\x1a\x68\x3a\xe5\x86\x53\xf6\xa6\x51\xae\x4f\x38\xb6\xeb\x9a\xe5\x62\xb9\x5e\xb0\x8f\x22\xb8\x7b\x79\xd3\x0f\xe4\x73\x28\x59\x6e\x89\x84\x7c\xd5\x72\xdd\x72\x01\x05\xcb\xb3\xd8\x8f\x69\xd7\x0b\xa8\x5b\xcd\xb2\x59\x2e\xa0\x68\xd5\xca\xd5\x69\x38\x76\xad\xe1\xd9\x66\xb9\x39\x8c\x6a\x23\x6f\x55\x59\xa8\x25\x8e\xb4\xc4\x91\x40\x6c\x36\x1c\x8f\xab\x2c\xc8\x32\xae\xd9\x9e\x85\x62\xb5\x71\x3b\xf5\x81\x8b\x7a\xa9\x51\x2c\x86\x63\xe8\x96\xc8\xd0\x34\x27\x87\x46\xe0\xb1\x28\xab\x50\x70\x78\xd3\xca\xae\x59\x74\xac\x89\xd0\x9a\x0f\xd7\xe4\x16\x16\x55\x76\x5c\xcf\x37\x28\xbb\xa6\x5d\xcf\x5b\x4d\x94\x9b\x3c\x69\xd0\x3b\xa6\x99\xb3\x87\x46\xe0\xfa\xf5\x61\xbf\xe5\xe6\xd4\xb0\xe9\x3a\x79\x16\xb7\x69\xa3\xcf\x05\x97\x45\x8c\xb0\x08\x16\x20\xc5\x9f\x39\xac\xf2\x55\x2b\x67\x57\xd9\xa0\x86\x6d\xf1\x5c\xcf\xaa\x35\xa9\x42\x23\xc3\xb8\xbd\xec\xd8\x26\x0d\xeb\x84\xdb\x30\x5d\x7b\xc2\x85\x5b\x41\x8e\x16\x9c\x59\xb0\xa7\xcc\x72\x11\xae\x93\x67\x5d\xe8\xdf\x47\xd8\xdd\xaf\x97\xeb\x85\x01\xb2\xf0\xef\x23\xa0\x59\x6f\xc3\x39\x6a\xce\x9d\x1c\xa6\xe9\xf2\x59\xe8\x36\xf2\x15\xbf\x40\x9a\xf8\xa6\xe9\x56\xcc\xdc\x64\xb1\x08\xc7\xf6\xfc\x15\x01\x36\x77\x4d\xc7\xce\x4f\xf1\x20\x9b\x48\x4d\x2b\x5f\xb1\xbd\x08\x30\xa3\x7c\xb9\xe0\xf0\xd5\x16\x5c\xc9\xd6\x56\x77\x75\x10\x1c\x8f\x05\xd2\x75\x88\x5c\x25\x7e\x6f\xb6\x52\x8d\x47\x4d\x4e\xf0\xfb\xd3\x72\x93\x43\xfc\x31\xfe\xa6\xd2\x32\x39\xc9\x83\xa3\x31\x69\x2a\x65\x91\xb2\x56\xef\x4c\xa8\x7a\x66\xd9\x0a\x7d\x91\xb2\x58\x03\x62\x59\xa5\xae\xab\xfa\x45\xa9\xad\xa9\x0b\x7a\xc6\x3a\x2f\xee\xb9\xa4\x07\x50\x13\x18\xeb\x04\xe2\xe7\x43\xd5\xb7\xa7\x52\x29\x20\xd1\x41\xcf\xef\x61\xa8\xfa\x58\xe7\x25\x3d\x64\x1d\xeb\x06\x16\x74\x2a\xaa\x9e\x4a\x11\x02\xc9\x34\x8b\x25\xd8\x92\x02\xda\x14\x85\xf2\x68\x5f\x8d\xb1\xce\xcd\x29\x20\x45\x99\xa5\x52\xdb\x53\xc0\xc2\xe1\xc0\x32\x01\xa4\x3b\x58\x59\xfa\x52\x65\xac\xf3\x82\x1e\xa0\x63\x1d\x80\x4c\x17\xc6\x3a\xfd\x5a\x01\x8b\x5a\xe6\x29\x60\x31\x3d\xe6\x3b\xd7\xb1\x34\x4b\xb2\x0a\x35\x62\xb4\xfb\xe1\x9d\x3d\x61\x13\xa8\x01\x4b\x13\x88\x2d\xf3\x25\x32\xec\x1a\x46\xac\x3b\xc4\x65\xc3\x58\xd9\x11\x62\xf7\xf0\x1c\xe3\x9e\x94\xe2\x77\xcd\xf2\x56\xeb\x12\xc0\x8a\x56\xeb\x12\xd4\xba\x95\x69\xf8\x30\xa3\x74\x10\x9f\xb3\x4c\xf1\x2d\x67\x94\x0e\x60\x55\x10\x4b\x51\xe7\x06\x51\x80\xd1\xd9\x0a\xe2\x61\x0d\x7c\x4b\x4b\xb2\x81\x5b\x18\x1d\xac\xd6\x44\x8a\xb5\x86\x6f\xf5\x2e\x00\xea\xe5\xf4\x43\x21\x3f\xfd\x82\x64\x82\x36\x56\xd0\xc6\xa8\x2e\x6d\x53\x03\xeb\x05\xf4\xb3\x24\x76\x3e\x9b\x93\x4f\x00\x88\xad\x45\x18\x5e\x17\x0f\xc3\x17\x24\xc3\x70\xef\xc2\x30\xdc\x97\xe1\x25\xc4\x59\x01\x2f\x52\x01\x7b\xc2\x02\xda\xfe\x1e\x40\xfb\x3f\xb2\x7a\x30\x3b\x4d\x61\x7b\x7b\x72\x01\x6b\xcb\x49\xda\xb5\x9f\x8a\xa5\xdf\x01\xa0\xd3\xeb\x80\xaa\xd3\xcf\x12\x25\x68\x02\x85\xfc\x84\x89\x78\xba\x53\x01\x3a\x32\x4f\xf0\xac\xe3\x2b\xd8\xdb\xca\x85\x0a\x90\x78\x24\x3d\xa0\x04\x39\x8c\x06\x39\x2c\x46\x7a\xb7\x02\x74\x52\x15\x98\xe9\xb5\x64\xba\x3a\x7d\x03\x99\x5e\xde\xea\x25\x2a\x11\x4b\xc4\xce\x54\x6e\xa0\x90\xba\x8a\xb2\x5b\x1a\x44\xa8\xab\x0e\xc4\x80\xae\xd8\x83\xec\x2d\x41\x5d\x9b\x8d\x01\xcb\x74\x16\x36\xee\x4e\x00\xdd\x1f\x0d\x0c\xd7\xdd\xa4\x01\x3d\xfb\x38\xd2\x8b\x6b\xf7\x48\x10\xb7\x9e\xf2\x44\xcf\x8c\x18\x79\x38\x88\x1c\xf0\x23\x5f\xe5\x4c\xab\xbf\x2b\xf6\xa0\x1f\xb7\xe9\x22\x1a\xe2\x9e\x12\x5f\xc0\xc7\xc4\xb8\xcd\x7b\xd8\xf0\xb7\x51\xa3\x59\x5f\xc7\x84\x7e\x5f\x2c\x84\x7b\x90\xbe\x9e\xbf\xab\xe2\x2b\xda\x5b\xe9\x15\x6c\xf8\x15\x40\x7b\x3b\x8d\x10\xde\x49\xc7\x43\xf8\x8f\x74\x32\x84\x1f\xa7\x17\x86\x70\x2a\x9d\x09\xe1\x27\xe9\x25\x21\xbc\x9b\xee\x0e\xe1\xa7\xe9\x95\x21\xfc\x2c\x6d\x84\xf0\xf3\xf4\xf9\x21\xfc\x22\xdd\x1b\xc2\x2f\xd3\xfd\x0c\xce\x8b\x03\xda\xe9\xf4\x60\x18\xf3\x9f\xe9\x5d\x21\xfc\x2a\xbd\x2f\x84\xf7\xd2\xfb\x43\x78\x3f\x3d\x1e\xc2\xaf\xd3\x07\x43\x80\x7e\x28\x04\x45\xbf\x29\x84\x98\x7e\x84\xc1\x00\x15\xaa\xea\x85\x10\xe2\xba\x17\x9a\x25\xf4\x8f\x85\xa0\xe9\x33\x21\xb4\xe9\xf7\xaf\x7c\x4e\x05\xb4\x76\x3d\xf9\xc0\x39\x49\xba\xb1\xc8\xad\x71\xa6\xc1\xef\x62\x9a\x2c\x5a\x4a\x7f\x24\x4c\xb7\x50\x3f\x1e\x42\x5a\xff\xdc\x4a\x85\x12\xe8\x7a\xf2\xc4\x39\x49\xba\xb1\xc8\xfb\x13\x4c\x83\x30\x4e\x1d\xfa\xd3\xc2\xa0\x27\x84\x70\x1c\xe9\xd1\x38\x1f\xe8\x2d\x5a\xc1\x1f\xa7\xbd\x94\x83\x9d\x41\x08\xc5\x4c\x2c\x84\x89\x8c\x3f\xea\x87\x09\x4a\x19\x2d\x84\x72\x66\x41\x08\xb7\x66\x92\x21\x54\x32\x6d\x0c\x2a\x04\xd5\x4c\x7b\x08\xb5\xcc\xc2\x10\xea\x19\x7d\xd5\xb7\xa8\x4d\x8d\x4c\xe6\x5c\x43\x6b\x64\x56\x7d\x9f\xa8\x99\x81\x91\xd4\x9a\x7e\xed\xa6\xc8\xf0\x36\x5e\x3b\x06\x4e\x26\x8e\x55\x29\x0a\x79\x19\x18\x86\xe6\x65\xc2\x11\x99\xe4\x86\x0c\xa6\xe8\xfd\x3f\xec\x96\xe9\xcc\x60\x98\xc9\x1d\x99\x61\x64\x0e\x24\xf8\x23\xa3\xdb\x7f\x56\xc5\x32\x85\x40\x59\xca\x94\xa4\x92\xd9\xcb\x95\x05\x3d\x99\x25\x7c\x91\x2d\x58\x91\xd9\x15\x3c\x6c\xce\x4d\x3f\x98\xe0\x1d\x3a\xae\xed\xd2\xc3\xd2\x76\xeb\x42\xd1\x7b\x74\x61\xe5\xec\xd5\x85\x95\xb3\x4f\x17\x56\xce\x98\x2e\xac\x9c\xcb\x74\x61\xe5\xec\xd7\xbb\xc3\x76\x5d\xa1\x0b\x2b\xe7\x4a\xbd\x3f\x84\xab\x74\x61\x49\x8c\xeb\xc3\x61\x9a\xab\xf5\x2d\x61\xcc\x01\xdd\x5f\x1f\x57\x6b\x80\x76\x8d\xbe\x1f\x99\x05\xbc\x69\xf1\xe5\x69\x4b\xe3\xcf\x7f\x23\xa9\x25\x83\x89\x99\x5c\x80\x30\x9c\x4c\x86\xe1\xb6\x4c\x18\x6e\xef\x06\xfe\xe8\x2d\x05\xdd\xbc\x73\x8e\xa8\xfe\x5f\x1b\xef\x42\x7a\x02\xc5\xf8\x99\xd2\x00\xe2\x5f\xe1\x67\xac\x60\x57\xe8\xe0\x61\x7a\x92\x76\xf3\x30\x3d\x09\xcf\xe1\xe1\x23\x00\xd6\xf3\x30\x3d\xe8\x86\x79\xf8\x38\x80\x1d\x3c\xfc\x02\x80\xcb\x78\xf8\x4d\x76\x76\xe5\xf9\x2b\xc0\x2d\x41\xfe\x0a\x50\x0f\xf2\x57\x80\xa9\x20\x7f\x05\xb8\x8b\xad\x18\xe0\x98\x02\xdc\x13\xd8\xc7\x80\xfb\x02\xfb\x18\xf0\x50\x60\x1f\x03\x1e\x0e\xea\x13\xf3\xeb\xc1\xea\x13\xf3\xdf\xc3\x58\x7d\x62\xc0\x53\x41\x7d\x62\xc0\xb3\x41\x7d\x54\xe0\x6b\x7c\xa7\x35\x54\xe0\x15\x1e\x3e\xae\x02\xdf\x09\xca\x8d\x03\x3f\x08\xca\x8d\x03\xa7\x82\x72\xfd\xbd\x9f\x8d\xc8\xb1\x38\xf0\x2b\xf8\xfe\x82\x17\xe2\x80\xa2\xf0\xfc\x13\x40\x3b\x0f\x1b\xbc\xff\x69\x6b\x1d\x4d\x00\x9d\x5c\x3f\x96\x00\x56\xfa\x03\x9f\xa4\x2c\xd7\xf8\x61\x7a\xca\xf8\x67\x5e\xff\x0a\xaa\xcb\xcf\xe0\xc0\xc0\x87\xb0\xe3\x55\xa4\x6e\x4f\x50\x3d\x2f\x55\x80\x36\xcc\xb9\xe8\x2d\x10\x57\xf0\xf2\x69\x1e\x5c\xc3\xf3\x4d\xb6\xfc\x3a\x61\xfa\x5b\x15\x20\x1d\x49\xdf\x13\xda\xa4\x3b\x98\xff\xc4\x9f\x5b\xb7\xcd\xad\x9f\x32\xe9\xeb\x0b\x69\x57\x7e\x28\xce\xda\x10\xa7\x8d\xfd\x0f\xe3\x61\x3d\x1f\xe7\x61\x6a\xcf\xe7\x79\x78\x54\xf0\xdd\xd0\xdc\xfb\x2a\x0f\xd3\xdc\xfb\x86\x9f\x50\x5f\xc4\xe7\xf3\x6b\x3e\x33\xef\x55\x12\x2d\xb7\x15\xeb\x93\x4e\xa1\x4f\xde\xe0\xe9\x96\xf0\x74\x3f\x88\xb3\x3b\x55\xbf\xf5\x4e\x41\x26\xef\x08\xfa\x62\xae\x53\x9a\x77\xfd\xf4\x6c\x81\x22\x21\x84\xc3\x03\xca\xff\xb3\xf3\x2f\x3f\x29\x9e\x79\x46\x14\xce\x6e\x93\x9b\x36\xce\xf5\x6d\xcc\xe7\x97\x08\x0f\x9f\xfe\xa9\x53\xe2\x32\x71\x2b\xcc\xcb\x40\xc1\xd0\x0f\x41\x87\x45\xdb\x1b\xfa\xef\x79\x6c\x06\xce\xf4\xf8\x94\xeb\x9e\xd1\xca\xb5\xd7\xf5\x9c\xc9\xbc\x67\xb4\x86\xd6\xb8\xd0\xad\xe4\xfa\xd0\x56\x2e\x1a\xbd\x2d\xd7\x4e\xaf\x5b\xc9\xf5\x1b\x8d\x62\xd1\xb5\xbd\x46\x31\x48\x63\x7b\xa5\x52\xc1\xe9\x37\x4a\xfe\x50\xf6\xf5\x19\xab\xb7\x19\xbb\x0f\xee\x33\xc7\xcd\xb1\xf1\x3e\xb4\x71\xc7\xc9\x8d\x83\x37\x1b\xdb\x8c\x4d\x1b\xb7\xfa\x99\xba\x95\xdc\x86\xed\xc1\xdc\x31\xb6\x6d\x33\xc6\x77\x5c\x7a\xf9\xee\x83\xe6\x55\xd7\x1e\xdc\x7b\xd5\xd8\x95\x7b\xfb\x8c\x3b\xd1\xd6\x46\x95\x74\x6c\xcf\xd8\x66\x9c\xe9\xca\xf1\x6b\xc3\x3c\x11\xc6\xfa\x33\x6a\x55\x6e\xb2\x4a\x15\xac\x42\xc1\xe9\xeb\x37\xd6\x05\xb5\x18\xba\xb9\xdf\x18\xee\xdb\xfa\x7f\x91\xb7\x2b\xcd\x9b\x39\x94\xbc\xde\x35\x51\x17\xde\x4d\xf5\x35\xfd\x46\x68\x4d\xa6\xec\x7c\xcf\xeb\x10\x71\x3e\xf5\xae\x6b\xf9\xcc\x5a\xa9\xfa\x78\xf7\xad\x66\xe9\xfc\x4e\x0a\x4a\x93\xb8\x07\xe7\x29\xb4\xcd\x34\xdd\xe9\x7a\xde\x2c\xda\x5e\xbe\x64\x5a\xf5\x82\x69\x15\x0a\xbd\xeb\x58\x9e\x1b\xb6\x87\x1e\x86\x7e\x83\x0d\x53\xd5\xae\x9f\x3d\x95\xe8\x8c\xe8\x37\x86\x3e\x6c\x31\x8e\x9d\x9f\xfa\x9f\x14\xe3\xa7\xa3\x62\x7e\x73\x8e\x53\x90\x3d\x8a\x3e\xbc\x3f\x31\xf4\x4a\xfa\x5e\xa9\xc0\xa5\x18\xdc\x6b\x56\xd3\x8d\xf8\x8b\x5a\x1e\x1b\x7a\x01\x31\x84\x07\x26\xfd\x55\x15\x7f\x43\x0f\x36\xcd\xbb\x94\xf0\x09\x9d\xe1\x7f\xa4\xf1\xef\x07\xb8\x4f\x01\x5e\x22\x83\xa3\xbe\x3d\xf1\xdb\xf4\xe2\x34\xe3\xdb\x8a\x6c\x70\x1e\x88\x01\xe9\xe3\xfe\xc7\x87\xfb\x04\x47\xfa\x16\xce\x3b\x62\x40\xea\x84\xbf\xa9\x04\xac\x9d\x00\xf6\x71\xbe\x95\xd2\x7f\x1e\x98\xe1\xfc\x37\xc4\xcf\x01\xaf\x72\x5e\xa3\x02\xb1\xbf\xf3\x5f\x58\x88\xaf\x50\x81\xf6\x57\x7d\x6f\x0e\xf1\x31\x3a\x60\xbc\x0e\x94\x38\xff\x9e\x0a\xa8\x6f\x00\x27\x15\xa1\xfc\xb7\x81\x53\x02\x6b\x6f\x03\xa7\x39\xbf\xa8\x02\x43\xa7\xd8\x21\xb1\xc5\xea\x29\x20\xc3\xf9\x34\xf1\xcf\xf8\xcb\x90\x02\xf4\xc5\x81\xa1\xf7\x81\x5e\x81\xd5\xf7\x81\x2d\x9c\x4d\x62\x28\xec\x85\x89\xf8\x01\xda\xd0\x32\x4a\xd0\xe5\x6c\xb3\xbc\xe3\x00\x92\x1f\x4d\x29\x0b\xf9\xfb\x5e\xb7\xb0\xb9\x8f\xc7\xc2\xf0\x41\x85\xf6\xc4\x57\xd8\xfb\xb8\xf2\x9e\x9e\x86\xa2\xb0\x7d\x96\x46\x31\xd7\x2c\x62\x60\xd2\x75\x06\xca\xf5\x7c\x75\xb2\x60\x0f\x9c\x21\x58\x6e\x6d\xc3\x84\x5d\xb7\x9d\x72\x7e\x6e\x44\xb5\x5c\x9f\x3c\xea\x7b\xf4\xab\xf6\x84\x95\x9f\xce\x96\xc0\xbf\xa8\x94\xec\x6a\xd3\x76\xdc\x6c\x89\x7a\x63\xee\x13\x5a\x01\x3d\xa4\x37\x54\xab\x23\xc3\xd9\x12\xed\xef\xa1\x3d\x4d\x75\x9e\x86\x6c\x4b\xb4\x91\xd3\xcc\x77\xfd\xa0\x98\x0f\x2b\x09\x71\x15\x6d\xad\x76\xaa\xab\x94\x84\xd6\x7e\x9e\x66\xa8\xb7\x18\x89\xb4\xa6\xf6\x1a\x09\x68\xea\x21\x23\x91\xd2\xd4\x0b\xb3\x09\x4d\x23\x75\xf5\xbd\x9a\x7a\xf5\x3d\x89\x98\xa6\x6e\x32\x34\xf5\x8a\x67\xd5\x4d\x46\xa2\x5d\x5b\x9d\xd0\xb6\x6b\xea\x65\x46\x42\xd5\xd4\xcd\x86\xa6\x8e\xfd\x1b\x25\xda\x6a\xb0\x44\x43\xda\xea\x84\xaa\x19\xda\x40\x62\x68\x90\x07\x94\xf3\x63\x31\x28\xf3\x7d\x5a\x63\xd7\xfd\xec\x1d\xe4\x27\xb3\xf3\xc7\x26\x25\xa9\x92\xe8\x97\xe8\xdb\x25\x7a\x55\xa2\xdf\x25\xd1\x7f\x5b\xa2\x1f\x97\xe8\x4f\x4a\xf4\xa7\x24\xfa\x73\x12\xfd\xaf\x25\xfa\xab\x12\xfd\x0d\x89\xfe\x43\x89\xfe\xae\x44\x7f\x4f\xa2\xcf\xfb\x51\x14\x49\x2c\x91\xe8\x17\x48\xf4\xf5\x12\x7d\x48\xa2\xef\x94\xe8\xd7\x49\xf4\x23\x12\xbd\x24\xd1\x9b\x12\xdd\x93\xe8\x47\x25\xfa\xdd\x12\xfd\x5e\x89\xfe\xfb\x12\xfd\x33\x12\xfd\x49\x89\xfe\x65\x89\xfe\x97\x12\xfd\x25\x89\xfe\x9a\x44\xff\x17\x89\x7e\x52\xa2\xbf\x25\xd1\x4f\x49\xf4\xf7\x24\x3a\x62\xf3\xeb\x6d\x12\x7d\x91\x44\xef\x96\xe8\xe7\x49\xf4\x0d\x12\x7d\x8b\x44\xdf\x29\xd1\xaf\x94\xe8\x87\x25\x7a\x5e\xa2\xd7\x24\xba\x2b\xd1\xef\x91\xe8\x33\x12\xfd\x13\x12\xfd\x53\x12\xfd\xb3\x12\xfd\x29\x89\xfe\xe7\x12\xfd\x45\x89\xfe\xb7\x12\xfd\x5b\x12\xfd\x0d\x89\xfe\xaf\x12\xfd\x47\x12\xfd\xc7\x12\xfd\xb4\x44\x9f\x95\xe8\x49\x75\x7e\x7d\x91\x44\x5f\x2e\xd1\x0d\x89\xbe\x5e\xa2\x7f\x44\xa2\x8f\x4a\xf4\x3d\x12\xfd\x2a\x89\x7e\x48\xa2\xdf\x28\xd1\x4b\x12\xbd\x29\xd1\x8f\x4a\xf4\xbb\x25\xfa\xef\x48\xf4\x87\x24\xfa\xa3\x12\xfd\xb8\x44\xff\xa2\x44\x7f\x46\xa2\xbf\x20\xd1\xbf\x2e\xd1\xbf\x29\xd1\x5f\x93\xe8\xdf\x95\xe8\x27\x25\xfa\x4f\x25\x7a\xcb\xf9\x14\xd1\xd3\x11\xfd\x15\xf6\xab\x62\x26\x62\xf9\x32\xd7\x5f\x8e\xe8\x7f\xc5\xf5\xe8\xbe\xf0\x2c\xd7\x8d\xc8\x7a\xf9\x32\xd7\x47\xe7\x59\x47\x2a\xe6\xad\x3c\xd4\xa8\x37\xaf\xa5\xb7\x4b\xf4\xce\x33\xb4\x1b\xd8\x07\xb8\x05\x2d\x0e\x9a\xfd\x7d\xe6\xf3\x0a\xcb\x0d\xce\x02\x6b\x98\x7d\xe8\x4c\x0e\x3e\xce\x8d\xb6\x3e\x64\x03\x0e\xf7\xb5\x81\xfb\x44\xeb\xc2\xe7\xd1\x76\xff\x74\xd3\xf2\xa7\xb5\x73\x07\x5d\x97\xc0\x0d\xfe\x6f\xb4\x02\xa6\x3a\xad\x42\x98\x7f\x95\xfb\xa0\x83\x78\xe6\x0f\x15\x98\xca\xde\x2d\x30\xb5\xee\x0a\x81\xe9\xed\xf9\x30\xe6\xd6\x37\x27\xc4\x77\x00\xb8\x55\x60\xea\xe5\x29\x81\x53\xf0\xfd\xd2\x01\x53\xdb\x3e\x21\x70\x1a\xc0\xa3\x02\xeb\x00\xfe\x44\x60\xfa\xfb\x82\xc0\x99\xd6\xbc\xf0\xeb\xd3\x6c\xcd\x37\x3f\x7e\x11\x80\x6f\x0b\x4c\x7d\xf7\x5d\x81\x3b\x5b\x1f\xa1\x7d\xa6\x31\xe9\x11\x78\x29\xf7\xb7\x07\x4c\x7d\x7d\xb9\xc0\xcb\x00\x54\x94\xb9\xfd\x3b\x2d\xc4\xd3\x99\xf0\x63\x02\xd7\x00\xcc\x08\xbc\x02\xc0\x1f\x08\xdc\x03\xe0\x31\x81\x37\x03\xf8\xb3\x48\xfa\x2f\x0a\x6c\x01\x78\x2e\x52\xfe\xd7\x23\xf6\xdf\x10\xf8\x08\x80\xef\x44\xec\x7f\x18\xb1\xff\xf7\x88\xfd\x2f\x22\xf6\x5a\x2c\x8c\xa7\xb9\xb6\x38\x36\x37\x7e\x4d\x24\xfe\x90\xc0\x26\xd5\x59\xe0\x95\x34\xc7\x05\x3e\x07\xc0\x9d\x02\xd3\xdc\x9d\x11\xf8\x5c\x00\x9f\x14\xd8\xa0\xfe\x12\x78\x35\xd0\x7a\x7f\x68\xe7\x6b\xee\x39\x81\xcf\xa3\xfe\x11\xf8\x7c\x9a\x1f\x02\xaf\x05\x5a\xfb\x3d\xf1\x3a\x00\xa7\x04\xbe\x00\xc0\xaf\x05\xee\xa5\xbb\x1a\x72\x1f\xcd\x09\x81\x2f\xa4\x32\x04\xa6\xb5\x37\x24\x30\x9d\x39\xb7\x0b\xbc\x81\xe6\x97\xc0\x59\xea\x3f\x81\x69\xad\xda\x02\x0f\xd2\x1a\x14\x78\x08\xc0\x5d\x02\x6f\xa4\xf3\xb0\xc0\x9b\x00\x7c\x4a\xe0\x61\x00\x4f\x08\xfc\x1b\x00\xbe\x2a\xf0\x08\x80\x7f\x10\xf8\x4a\x00\xdf\x13\x78\x1c\xc0\x5b\x02\x5f\x1d\x7c\x8c\xe1\x7c\x80\xd6\x8c\xc0\xb7\x00\xd8\x21\x30\x3d\x5b\x2e\x13\x98\xe6\xfb\xf5\x02\x5f\x04\xa0\x20\xf0\x56\x00\xb7\x09\x7c\x31\x80\xdf\x12\xf8\x12\x00\xbf\x2b\xf0\x28\x80\x47\x04\xde\x01\xe0\x8f\x05\xde\x09\xe0\x4b\x02\xef\x02\xf0\xbc\xc0\xf4\x2c\x3c\x29\xf0\x1e\x00\x3f\x17\x78\x1f\x3d\x63\x12\x21\x8f\xd1\x9c\x15\xf8\x32\x1a\x53\x81\x2f\xa7\x36\x09\xbc\x9f\xfe\x04\xfe\x08\x80\x6b\x04\xde\x42\x7d\x26\xf0\x76\x1a\x7f\x81\xb7\xd1\x33\x4f\xe0\x4b\x69\xfd\x08\xbc\x17\xc0\xbd\x02\x5f\x05\xe0\x21\x81\x6f\x06\xf0\x69\x81\xaf\x01\x70\x22\x31\x77\xfe\xfd\x85\xc0\xf4\x3c\x7f\x51\x60\x5a\x7f\xaf\x08\x4c\xeb\xf5\x0d\x81\x69\x7d\xfd\x48\xe0\x83\xf4\x3c\x11\x98\x7d\xdf\xd4\x42\xbe\x8e\x9e\xe9\x02\x5f\x4f\xcf\x04\x81\x0f\xd1\x9a\x12\x98\xf6\xa2\xcd\x02\xd3\x9e\xbc\x4b\xe0\x1b\x29\x4f\x81\x6f\xa2\xfd\x4a\xe0\x22\xed\x57\x02\xd3\x5e\x36\x25\x70\x9e\xf6\x2b\x81\x0b\xb4\x5f\x09\x6c\xd3\x1c\x13\x5e\x31\x9a\xc2\x7a\x05\xdf\x1f\x45\xbf\x52\x55\xf8\x36\x18\xf0\x78\x84\x8f\x44\xb8\x19\xe1\x63\x11\x7e\x20\xc2\xc7\x23\xfc\x74\x84\x5f\x88\xf0\xab\x11\x7e\x33\xc2\xa7\x22\x2c\xfa\x6f\x88\x33\x11\x36\x22\x3c\x18\xe1\xd1\x08\x8f\x47\xf8\x48\x84\x9b\x11\x3e\x16\xe1\x07\x22\xbc\x92\x87\x83\xfd\xe8\x7b\x11\xbe\xcd\x69\x22\x5b\xb0\x73\x93\x13\xa6\x95\xcb\x39\xf6\x14\xb2\x9e\x7d\xd4\x43\xd6\xb1\xab\xd9\x9d\x07\xf7\x64\x09\x42\x1f\x3e\xf3\xd6\x73\x7b\xd7\x73\x7c\x33\x1f\xcb\xf5\x62\x03\xd9\x6a\x75\xaa\x66\x5a\x85\x82\xe3\x96\x27\x42\x67\xbf\x60\x56\x2d\xd7\x39\xdb\x25\xb3\xe8\x58\x35\x3b\xc8\xaf\xda\xc8\x47\xfc\xb3\x59\xd7\x73\x3c\x2b\x87\xac\x3b\x5d\x63\x77\x5e\x29\xec\xdf\xb9\x73\xd0\xfc\x88\x7f\xdb\xe2\xdf\x46\xfc\xdb\xb0\x7f\xdb\xc4\x6c\x83\x2f\x79\xe1\xb7\xbd\xac\xd3\x28\x58\x9e\x45\x19\x0f\x65\x87\xf0\xbf\xbf\x1e\x15\xfe\xcd\x83\x78\xfd\x29\x7f\x91\x8c\xfa\xfd\xa2\x6e\x99\x0e\xae\x69\x11\x7d\x54\x52\x5e\xf4\x98\xf1\x4f\x67\x49\x3f\x1e\x39\x07\x44\x3d\xbe\xdf\xc6\x19\xdf\xf2\xd9\xb5\x65\x9d\x7f\x0f\xfc\xfb\x5d\xbc\x9d\x41\xfa\x40\xef\xe7\xe5\x47\xfb\xe0\x01\x5e\xee\x92\xb3\xd4\xff\x6d\x9e\x7e\x63\x44\xff\x1c\x4f\xbf\x3e\xa2\x2b\x91\xfb\x8d\x92\xf2\x5f\x89\xcd\x5f\x5e\xb4\xff\x87\xb8\x36\x18\xd1\xbf\xc9\xd3\x77\xc7\x3f\xb8\xfc\xbb\xe7\xc9\x93\xae\xb7\xf8\x80\x7c\xe9\x2c\xe5\x2b\x92\xf4\x9f\xe1\x47\xa9\xfb\x95\x0f\x4e\x3f\x2a\x49\xdf\xc7\x07\xf5\xd3\xda\x07\xa7\xbf\x58\x32\xfe\xfb\xf8\xf8\x3f\xcd\xeb\xd1\x25\xfc\x1f\x0a\x08\xe3\xff\x05\x49\xf9\x5f\xeb\xf0\xef\x77\x27\x3f\xb8\xfc\x27\x25\xe5\x9f\xde\xe0\xdf\x83\xcf\x7f\x5d\xfc\x3c\x14\x2d\xbf\x47\x52\xfe\x6e\xfe\x01\xea\xf8\x59\xfa\x6f\xa9\xa4\xfc\xee\xac\x7f\x0f\x9e\xb7\x5d\x7c\xad\x46\xcb\xbf\x9d\xe7\x19\x3d\x6e\x9f\xe4\xff\xa0\x25\x3a\xaf\xa2\xeb\xcf\x95\x94\x3f\x33\x30\xb7\x9c\x2e\x7e\x7e\x8b\x96\x3f\x21\x69\x7f\x37\x3f\xf8\x1e\x3a\x4b\xfb\xf3\x92\xf2\x1f\x99\xa7\xfc\xce\x79\xca\xa7\x77\x36\x75\xff\x6c\x23\xb2\x15\xe3\x04\x4f\xaf\x0a\xe9\xe7\x2b\xff\xb1\x79\xfa\x8e\xae\xe6\x0a\xff\xfe\x72\x7b\x98\xae\x29\x94\x1f\x7c\x5f\xfc\xaf\x00\x00\x00\xff\xff\x41\xb4\x94\x3b\x68\x36\x00\x00")

func netcostBpfOBytes() ([]byte, error) {
	return bindataRead(
		_netcostBpfO,
		"netcost-bpf.o",
	)
}

func netcostBpfO() (*asset, error) {
	bytes, err := netcostBpfOBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "netcost-bpf.o", size: 13928, mode: os.FileMode(436), modTime: time.Unix(1, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"netcost-bpf.o": netcostBpfO,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"netcost-bpf.o": &bintree{netcostBpfO, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

