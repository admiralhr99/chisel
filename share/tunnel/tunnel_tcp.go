// Package tunnel provides TCP tunneling with Reality authentication
package tunnel

import (
	"io"
	"net"
	"sync"
	"time"
)

// TCPRelay provides fast bidirectional TCP relay without SSH overhead
type TCPRelay struct {
	BufferSize int
}

// NewTCPRelay creates a new TCP relay with specified buffer size
func NewTCPRelay(bufferSize int) *TCPRelay {
	if bufferSize <= 0 {
		bufferSize = 32 * 1024 // 32KB default
	}
	return &TCPRelay{BufferSize: bufferSize}
}

// Relay bidirectionally copies data between two connections
func (r *TCPRelay) Relay(client, target net.Conn) (int64, int64, error) {
	var clientToTarget, targetToClient int64
	var wg sync.WaitGroup
	var err1, err2 error

	// Set timeouts
	client.SetDeadline(time.Time{}) // No deadline
	target.SetDeadline(time.Time{})

	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		clientToTarget, err1 = r.copy(target, client)
		target.SetReadDeadline(time.Now()) // Unblock the other copy
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		targetToClient, err2 = r.copy(client, target)
		client.SetReadDeadline(time.Now()) // Unblock the other copy
	}()

	wg.Wait()

	if err1 != nil && err1 != io.EOF {
		return clientToTarget, targetToClient, err1
	}
	return clientToTarget, targetToClient, err2
}

// copy with buffer pool for efficiency
func (r *TCPRelay) copy(dst, src net.Conn) (int64, error) {
	buf := make([]byte, r.BufferSize)
	return io.CopyBuffer(dst, src, buf)
}
