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
	io.ByteScanner
	GetPublicKey() *[32]byte
	GetServerPublicKey() *[32]byte
}

type conn struct {
	net.Conn
	bufferedRead    *bufio.Reader
	lastRead        []byte
	isUnread        bool
	privateKey      *[32]byte
	PublicKey       *[32]byte
	ServerPublicKey *[32]byte
	sharedKey       *[32]byte
	buffer          []byte
}

func (c conn) GetPublicKey() *[32]byte {
	return c.PublicKey
}

func (c conn) GetServerPublicKey() *[32]byte {
	return c.ServerPublicKey
}

func (c conn) ReadByte() (b byte, err error) {
	if !c.isUnread {
		c.lastRead = make([]byte, 1)
		_, err = c.Read(c.lastRead)
	}
	b = c.lastRead[0]
	c.isUnread = false
	return
}

func (c conn) UnreadByte() (err error) {
	c.isUnread = true
	return
}

func (c conn) Read(b []byte) (n int, err error) {
	copied := copy(b, c.buffer)
	newBuf := make([]byte, len(c.buffer)-copied)
	c.buffer = newBuf
	if copied < len(b) {
		n, err = c.unbufferedRead(b[copied:])
		if err != nil {
			return
		}
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

	lengthCode, success := box.OpenAfterPrecomputation([]byte{}, header, &nonce, c.sharedKey)
	if !success {
		err = errors.New("OpenAfterPrecomputation failed on header")
		return
	}
	length := binary.LittleEndian.Uint32(lengthCode)

	n, err = io.ReadFull(c.bufferedRead, nonce[:])
	if err != nil {
		return
	}

	data := make([]byte, length)
	n, err = io.ReadFull(c.bufferedRead, data)
	if err != nil {
		return
	}

	decrypted, success := box.OpenAfterPrecomputation([]byte{}, data, &nonce, c.sharedKey)
	if !success {
		err = errors.New("OpenAfterPrecomputation failed on data")
		return
	}

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
	var writebuf []byte
	outLen := len(b) + box.Overhead
	var nonce [24]byte
	n, err = rand.Read(nonce[:])
	if err != nil {
		return
	}
	writebuf = append(writebuf, nonce[:]...)

	length := make([]byte, 4)
	lengthIn := uint32(outLen)
	binary.LittleEndian.PutUint32(length, lengthIn)
	writebuf = append(writebuf, box.SealAfterPrecomputation([]byte{}, length, &nonce, c.sharedKey)...)
	if err != nil {
		return
	}

	n, err = rand.Read(nonce[:])
	if err != nil {
		return
	}
	writebuf = append(writebuf, nonce[:]...)
	if err != nil {
		return
	}

	writebuf = append(writebuf, box.SealAfterPrecomputation([]byte{}, b, &nonce, c.sharedKey)...)
	return c.Conn.Write(writebuf)
}

func GenerateKeys() (pub, priv, elligator [32]byte, err error) {
	for {
		_, err = io.ReadFull(rand.Reader, priv[:])
		if err != nil {
			return
		}
		if extra25519.ScalarBaseMult(&pub, &elligator, &priv) {
			break
		}
	}
	return
}

// This generates a keypair for the connection
func Wrap(oc net.Conn) (nc Conn, err error) {
	pub, priv, elligator, err := GenerateKeys()
	if err != nil {
		return
	}
	return WrapWithKeys(oc, pub, priv, elligator)
}

// This allows reusing a previously generated keypair for the connection
func WrapWithKeys(oc net.Conn, pub, priv, elligator [32]byte) (nc Conn, err error) {
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
		Conn:            oc,
		bufferedRead:    bRead,
		lastRead:        make([]byte, 1),
		isUnread:        false,
		privateKey:      &priv,
		PublicKey:       &pub,
		ServerPublicKey: &serverKey,
		sharedKey:       &shared,
	}
	return
}
