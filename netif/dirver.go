package netif

import "io"

type Driver interface {
	io.Reader
	io.Writer
	Input([]byte) (int, error)
	Output([]byte) (int, error)
}
