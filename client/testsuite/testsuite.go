package testsuite

import (
	"bufio"
	"fmt"
	"net"
)

const Port = 8082

type TestSuite struct {
	server      net.Listener
	connections []net.Conn
}

func NewTestSuite(network string) (*TestSuite, error) {
	s, err := net.Listen(network, fmt.Sprintf("127.0.0.1:%d", Port))
	if err != nil {
		return nil, err
	}
	return &TestSuite{
		server:      s,
		connections: make([]net.Conn, 0, 1),
	}, nil
}

func (ts *TestSuite) Close() error {
	for _, c := range ts.connections {
		err := c.Close()
		if err != nil {
			return err
		}
	}
	return ts.server.Close()
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
		ts.connections = append(ts.connections, conn)

		go handleConn(conn) // отдельная goroutine на клиента
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	addr := conn.RemoteAddr().String()
	fmt.Println("client connected:", addr)

	conn.Write([]byte("hello\n"))

	reader := bufio.NewReader(conn)

	for {
		msg, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("client disconnected:", addr)
			return
		}

		fmt.Printf("recv [%s]: %s", addr, msg)
	}
}
