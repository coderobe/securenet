package securenet

import (
	"net"
)

func Dial(network, address string) (c Conn, err error) {
	c, err = net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	c, err = Wrap(c)
	return
}
