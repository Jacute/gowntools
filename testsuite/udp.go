package testsuite

import (
	"fmt"
	"net"
	"sync"
)

type UDPServer struct {
	server *net.UDPConn
	wg     *sync.WaitGroup
}

func NewUDPServer() (*UDPServer, error) {
	ts := &UDPServer{
		wg: &sync.WaitGroup{},
	}
	s, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		return nil, err
	}
	ts.server = s
	return ts, nil
}

func (ts *UDPServer) Close() error {
	return ts.server.Close()
}

func (ts *UDPServer) Listen() {
	buf := make([]byte, 32)
	for {
		n, addr, err := ts.server.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		_, err = ts.server.WriteToUDP([]byte(fmt.Sprintf("echo: %s", buf[:n])), addr)
		if err != nil {
			fmt.Printf("error writing: %s", err.Error())
		}
	}
}

func (ts *UDPServer) Address() string {
	return ts.server.LocalAddr().String()
}
