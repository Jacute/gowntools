package testsuite

import (
	"bufio"
	"fmt"
	"net"
	"sync"
)

type TestSuite struct {
	server net.Listener
	wg     *sync.WaitGroup
	conns  []net.Conn
	mu     sync.Mutex
}

func NewTestSuite(network string) (*TestSuite, error) {
	s, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &TestSuite{
		server: s,
		wg:     &sync.WaitGroup{},
	}, nil
}

func (ts *TestSuite) Close() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, c := range ts.conns {
		c.Close()
	}
	err := ts.server.Close()
	return err
}

func (ts *TestSuite) Address() string {
	return ts.server.Addr().String()
}

// Listen start accepting connection
//
// Blocking function
func (ts *TestSuite) Listen() {
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

	conn.Write([]byte("hello\n"))

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
