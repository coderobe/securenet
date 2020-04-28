package securenet

import (
	"net"
)

func Dial(network, address string) (c Conn, err error) {
	oC, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	c, err = Wrap(oC)
	return
}
