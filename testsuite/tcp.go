package testsuite

import (
	"bufio"
	"fmt"
	"net"
	"sync"
)

type TCPServer struct {
	server net.Listener
	wg     *sync.WaitGroup
	conns  []net.Conn
	mu     sync.Mutex
}

func NewTCPServer() (*TCPServer, error) {
	ts := &TCPServer{
		wg: &sync.WaitGroup{},
	}
	s, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ts.server = s
	return ts, nil
}

func (ts *TCPServer) Close() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, c := range ts.conns {
		c.Close()
	}
	err := ts.server.Close()
	return err
}

func (ts *TCPServer) Address() string {
	return ts.server.Addr().String()
}

// Listen start accepting connection
//
// Blocking function
func (ts *TCPServer) Listen() {
	for {
		conn, err := ts.server.Accept()
		if err != nil {
			if err == net.ErrClosed {
				return
			}
			continue
		}
		ts.mu.Lock()
		ts.conns = append(ts.conns, conn)
		ts.mu.Unlock()

		go handleConn(conn) // отдельная goroutine на клиента
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	addr := conn.RemoteAddr().String()
	fmt.Println("client connected:", addr)

	_, err := conn.Write([]byte("hello\n"))
	if err != nil {
		fmt.Printf("error writing: %s", err.Error())
		return
	}

	reader := bufio.NewReader(conn)

	msg, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("client disconnected:", addr)
		return
	}
	msg = msg[:len(msg)-1]

	fmt.Printf("recv [%s]: %s\n", addr, msg)
	fmt.Fprintf(conn, "echo: %s\n", string(msg))
}
