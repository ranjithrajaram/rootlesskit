package tcp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"github.com/rootless-containers/rootlesskit/v2/pkg/port"
	"github.com/rootless-containers/rootlesskit/v2/pkg/port/builtin/msg"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func Run(socketPath string, spec port.Spec, stopCh <-chan struct{}, stoppedCh chan error, logWriter io.Writer) error {
	ln, err := net.Listen(spec.Proto, net.JoinHostPort(spec.ParentIP, strconv.Itoa(spec.ParentPort)))
	if err != nil {
		fmt.Fprintf(logWriter, "listen: %v\n", err)
		return err
	}
	newConns := make(chan net.Conn)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				fmt.Fprintf(logWriter, "accept: %v\n", err)
				close(newConns)
				return
			}
			newConns <- c
		}
	}()
	go func() {
		defer func() {
			stoppedCh <- ln.Close()
			close(stoppedCh)
		}()
		for {
			select {
			case c, ok := <-newConns:
				if !ok {
					return
				}
				go func() {
					if err := copyConnToChild(c, socketPath, spec, stopCh); err != nil {
						fmt.Fprintf(logWriter, "copyConnToChild: %v\n", err)
						return
					}
				}()
			case <-stopCh:
				return
			}
		}
	}()
	// no wait
	return nil
}

func copyConnToChild(c net.Conn, socketPath string, spec port.Spec, stopCh <-chan struct{}) error {
	defer c.Close()
	// get fd from the child as an SCM_RIGHTS cmsg
	fd, err := msg.ConnectToChildWithRetry(socketPath, spec, 10)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "")
	defer f.Close()
	fc, err := net.FileConn(f)
	if err != nil {
		return err
	}
	defer fc.Close()
	bicopy(c, fc, stopCh)
	return nil
}

var errQuit = errors.New("quit")

const maxSpliceSize = 65536

func spliceCopy(rawDst, rawSrc syscall.RawConn, quit <-chan struct{}) error {
	var pipeFds [2]int
	if err := unix.Pipe2(pipeFds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return err
	}
	pipeRead := pipeFds[0]
	pipeWrite := pipeFds[1]
	defer unix.Close(pipeRead)
	defer unix.Close(pipeWrite)

	for {
		select {
		case <-quit:
			return nil
		default:
		}

		var n int
		var err error
		readErr := rawSrc.Read(func(fd uintptr) bool {
			var sn int64
			sn, err = unix.Splice(int(fd), nil, pipeWrite, nil, maxSpliceSize, unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
			n = int(sn)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				select {
				case <-quit:
					err = errQuit
					return true
				default:
				}
				return false
			}
			return true
		})

		if readErr != nil {
			return readErr
		}
		if err != nil {
			if err == errQuit {
				return nil
			}
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			return nil
		}

		inPipe := n
		for inPipe > 0 {
			var m int
			writeErr := rawDst.Write(func(fd uintptr) bool {
				var sm int64
				sm, err = unix.Splice(pipeRead, nil, int(fd), nil, inPipe, unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
				m = int(sm)
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					select {
					case <-quit:
						err = errQuit
						return true
					default:
					}
					return false
				}
				return true
			})

			if writeErr != nil {
				return writeErr
			}
			if err != nil {
				if err == errQuit {
					return nil
				}
				if err == unix.EINTR {
					continue
				}
				return err
			}
			if m == 0 {
				return io.ErrUnexpectedEOF
			}
			inPipe -= m
		}
	}
}

var (
	spliceSupported bool
	probeOnce       sync.Once
)

// probeSplice checks if the splice(2) system call is supported between socket and pipe and not blocked by seccomp
func probeSplice() bool {
	probeOnce.Do(func() {
		// Create a socket pair to test socket -> pipe splicing
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			logrus.Debugf("splice support probe failed to create socketpair: %v (splice will be disabled)", err)
			return
		}
		defer syscall.Close(fds[0])
		defer syscall.Close(fds[1])

		var pipeFds [2]int
		if err := unix.Pipe2(pipeFds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			logrus.Debugf("splice support probe failed to create pipe: %v (splice will be disabled)", err)
			return
		}
		defer unix.Close(pipeFds[0])
		defer unix.Close(pipeFds[1])

		_, err = unix.Splice(fds[0], nil, pipeFds[1], nil, 0, unix.SPLICE_F_NONBLOCK)
		if err != nil {
			if err != unix.EAGAIN && err != unix.EWOULDBLOCK && err != unix.EINTR {
				logrus.Debugf("splice support probe failed: %v (splice will be disabled)", err)
				return
			}
		}
		spliceSupported = true
	})
	return spliceSupported
}

// bicopy is based on libnetwork/cmd/proxy/tcp_proxy.go .
// NOTE: sendfile(2) cannot be used for sockets
func bicopy(x, y net.Conn, quit <-chan struct{}) {
	// Guard lifetime of net.Conn objects so they are not finalized/closed by GC while splicing
	defer runtime.KeepAlive(x)
	defer runtime.KeepAlive(y)

	sconnX, okX := x.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	sconnY, okY := y.(interface {
		SyscallConn() (syscall.RawConn, error)
	})

	// Fallback to standard io.Copy if we cannot get raw fds or splice is unavailable/blocked
	if !okX || !okY || !probeSplice() {
		var wg sync.WaitGroup
		var broker = func(to, from net.Conn) {
			io.Copy(to, from)
			if fromTCP, ok := from.(*net.TCPConn); ok {
				fromTCP.CloseRead()
			}
			if toTCP, ok := to.(*net.TCPConn); ok {
				toTCP.CloseWrite()
			}
			wg.Done()
		}

		wg.Add(2)
		go broker(x, y)
		go broker(y, x)
		finish := make(chan struct{})
		go func() {
			wg.Wait()
			close(finish)
		}()

		select {
		case <-quit:
		case <-finish:
		}
		x.Close()
		y.Close()
		<-finish
		return
	}

	rawX, errX := sconnX.SyscallConn()
	rawY, errY := sconnY.SyscallConn()
	if errX != nil || errY != nil {
		var wg sync.WaitGroup
		var broker = func(to, from net.Conn) {
			io.Copy(to, from)
			if fromTCP, ok := from.(*net.TCPConn); ok {
				fromTCP.CloseRead()
			}
			if toTCP, ok := to.(*net.TCPConn); ok {
				toTCP.CloseWrite()
			}
			wg.Done()
		}

		wg.Add(2)
		go broker(x, y)
		go broker(y, x)
		finish := make(chan struct{})
		go func() {
			wg.Wait()
			close(finish)
		}()

		select {
		case <-quit:
		case <-finish:
		}
		x.Close()
		y.Close()
		<-finish
		return
	}

	// We use the raw splice event loop
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := spliceCopy(rawY, rawX, quit); err != nil {
			logrus.Debugf("spliceCopy x->y error: %v", err)
		}
		if yTCP, ok := y.(*net.TCPConn); ok {
			yTCP.CloseWrite()
		}
		if xTCP, ok := x.(*net.TCPConn); ok {
			xTCP.CloseRead()
		}
	}()

	go func() {
		defer wg.Done()
		if err := spliceCopy(rawX, rawY, quit); err != nil {
			logrus.Debugf("spliceCopy y->x error: %v", err)
		}
		if xTCP, ok := x.(*net.TCPConn); ok {
			xTCP.CloseWrite()
		}
		if yTCP, ok := y.(*net.TCPConn); ok {
			yTCP.CloseRead()
		}
	}()

	finish := make(chan struct{})
	go func() {
		wg.Wait()
		close(finish)
	}()

	select {
	case <-quit:
	case <-finish:
	}
	x.Close()
	y.Close()
	<-finish
}
