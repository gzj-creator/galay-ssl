package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
)

func usage(program string) string {
	return fmt.Sprintf("usage: %s <port> <cert_file> <key_file> [backlog]", program)
}

func parseArgs(args []string) (uint16, string, string, int, error) {
	if len(args) < 4 {
		return 0, "", "", 0, errors.New(usage(args[0]))
	}

	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		return 0, "", "", 0, fmt.Errorf("invalid port %q: %w", args[1], err)
	}

	backlog := 4096
	if len(args) >= 5 {
		parsed, err := strconv.Atoi(args[4])
		if err != nil {
			return 0, "", "", 0, fmt.Errorf("invalid backlog %q: %w", args[4], err)
		}
		if parsed < 128 {
			parsed = 128
		}
		backlog = parsed
	}

	return uint16(port), args[2], args[3], backlog, nil
}

func loadTLSConfig(certFile string, keyFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{certificate},
		SessionTicketsDisabled: true,
	}, nil
}

func listenWithBacklog(port uint16, backlog int) (net.Listener, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = syscall.Close(fd)
		}
	}()

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}

	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: int(port)}); err != nil {
		return nil, err
	}

	if err := syscall.Listen(fd, backlog); err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("go-crypto-tls-server:%d", port))
	if file == nil {
		return nil, errors.New("failed to create listener file")
	}
	defer file.Close()

	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	cleanup = false
	return listener, nil
}

func writeAll(conn net.Conn, payload []byte) error {
	written := 0
	for written < len(payload) {
		n, err := conn.Write(payload[written:])
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}

	return nil
}

func handleConn(conn *tls.Conn) {
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "handshake error: %v\n", err)
		return
	}

	buffer := make([]byte, 64*1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			}
			return
		}

		if err := writeAll(conn, buffer[:n]); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			return
		}
	}
}

func main() {
	port, certFile, keyFile, backlog, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	config, err := loadTLSConfig(certFile, keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls config error: %v\n", err)
		os.Exit(1)
	}

	listener, err := listenWithBacklog(port, backlog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	tlsListener := tls.NewListener(listener, config)
	fmt.Printf("Go TLS bench server listening on port %d\n", port)

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept error: %v\n", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			fmt.Fprintln(os.Stderr, "accept error: non-TLS connection")
			conn.Close()
			continue
		}

		go handleConn(tlsConn)
	}
}
