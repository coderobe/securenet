package securenet

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/coderobe/ed25519/extra25519"
	"golang.org/x/crypto/nacl/box"
)

type Conn interface {
	net.Conn
}

type conn struct {
	net.Conn
	bufferedRead            *bufio.Reader
	privateKey              *[32]byte
	PublicKey               *[32]byte
	ServerPublicKey         *[32]byte
	sharedKey               *[32]byte
	elligatorRepresentative *[32]byte
	buffer                  []byte
}

type reReader struct {
	io.Reader
	internalConn Conn
}

func (r reReader) Read(b []byte) (n int, err error) {
	return r.internalConn.Read(b)
}

func (c conn) Read(b []byte) (n int, err error) {
	copied := copy(c.buffer, b)
	if copied < len(b) {
		n, err = io.ReadFull(reReader{internalConn: c}, b[copied:])
	}
	return
}

func (c conn) unbufferedRead(b []byte) (n int, err error) {
	var nonce [24]byte
	n, err = io.ReadFull(c.bufferedRead, nonce[:])
	if err != nil {
		return
	}

	header := make([]byte, box.Overhead+4) // length: box overhead + len(uint32)
	n, err = io.ReadFull(c.bufferedRead, header)
	if err != nil {
		return
	}

	lengthCode := make([]byte, 4)
	box.OpenAfterPrecomputation(lengthCode, header, &nonce, c.sharedKey)

	n, err = io.ReadFull(c.bufferedRead, nonce[:])
	if err != nil {
		return
	}

	length := binary.BigEndian.Uint32(lengthCode)

	n, err = io.ReadFull(c.bufferedRead, nonce[:])
	if err != nil {
		return
	}
	data := make([]byte, box.Overhead+length)
	n, err = io.ReadFull(c.bufferedRead, data)
	if err != nil {
		return
	}

	decrypted := make([]byte, length)
	box.OpenAfterPrecomputation(decrypted, data, &nonce, c.sharedKey)

	copied := copy(b, decrypted)
	if copied < len(decrypted) {
		c.buffer = make([]byte, len(decrypted)-copied)
		copied += copy(c.buffer, decrypted[copied:])
		if copied != len(decrypted) {
			err = errors.New("Copied wrong amount of bytes")
		}
	}

	return
}

func (c conn) Write(b []byte) (n int, err error) {
	length := make([]byte, 4)
	out := make([]byte, len(length)+box.Overhead)
	binary.BigEndian.PutUint32(length, uint32(len(out)))
	var nonce [24]byte
	n, err = rand.Read(nonce[:])
	if err != nil {
		return
	}
	box.SealAfterPrecomputation(out, length, &nonce, c.sharedKey)
	n, err = c.Conn.Write(nonce[:])
	if err != nil {
		return
	}
	n, err = c.Conn.Write(out)
	if err != nil {
		return
	}

	out = make([]byte, len(b)+box.Overhead)
	n, err = rand.Read(nonce[:])
	if err != nil {
		return
	}
	box.SealAfterPrecomputation(out, b, &nonce, c.sharedKey)
	n, err = c.Conn.Write(nonce[:])
	if err != nil {
		return
	}
	return c.Conn.Write(out)
}

func Wrap(oc net.Conn) (nc Conn, err error) {
	var pub [32]byte
	var priv [32]byte
	var elligator [32]byte
	for {
		_, err = io.ReadFull(rand.Reader, priv[:])
		if err != nil {
			return
		}
		if extra25519.ScalarBaseMult(&pub, &elligator, &priv) {
			break
		}
	}

	_, err = oc.Write(elligator[:])
	if err != nil {
		return
	}

	bRead := bufio.NewReader(oc)
	var serverKeyElligator [32]byte
	_, err = io.ReadFull(bRead, serverKeyElligator[:])
	if err != nil {
		return
	}
	var serverKey [32]byte
	extra25519.RepresentativeToPublicKey(&serverKey, &serverKeyElligator)

	var shared [32]byte
	box.Precompute(&shared, &serverKey, &priv)

	nc = conn{
		Conn:                    oc,
		bufferedRead:            bRead,
		privateKey:              &priv,
		PublicKey:               &pub,
		ServerPublicKey:         &serverKey,
		sharedKey:               &shared,
		elligatorRepresentative: &elligator,
	}
	return
}
