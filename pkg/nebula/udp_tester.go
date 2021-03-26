// +build e2e_testing

package nebula

import (
	"net"
	"sync"
)

type UdpPacket struct {
	IP   net.IP
	Port uint16
	Data []byte
}

type udpConn struct {
	addr *udpAddr

	// Packets to receive into nebula
	rxPackets chan *UdpPacket

	txLock sync.Mutex
	// Packets transmitted outside by nebula
	txPackets []*UdpPacket
}

func NewListener(ip string, port int, multi bool) (*udpConn, error) {
	rxChan := make(chan *UdpPacket)
	return &udpConn{
		addr:      &udpAddr{net.ParseIP(ip), uint16(port)},
		rxPackets: rxChan,
		txPackets: make([]*UdpPacket, 0),
	}, nil
}

func (u *udpConn) Send(packet *UdpPacket) {
	u.rxPackets <- packet
}

func (u *udpConn) Get() *UdpPacket {
	u.txLock.Lock()
	defer u.txLock.Unlock()

	if len(u.txPackets) == 0 {
		return nil
	}

	p := u.txPackets[0]
	u.txPackets = u.txPackets[1:]
	return p
}

func (u *udpConn) WriteTo(b []byte, addr *udpAddr) error {
	u.txLock.Lock()
	p := &UdpPacket{
		Data: make([]byte, len(b), len(b)),
		IP:   make([]byte, len(addr.IP)),
		Port: addr.Port,
	}

	copy(p.Data, b)
	copy(p.IP, addr.IP)

	u.txPackets = append(u.txPackets, p)
	return nil
}

func (u *udpConn) ListenOut(f *Interface, q int) {
	plaintext := make([]byte, mtu)
	header := &Header{}
	fwPacket := &FirewallPacket{}
	ua := &udpAddr{}
	nb := make([]byte, 12, 12)

	lhh := f.lightHouse.NewRequestHandler()
	conntrackCache := NewConntrackCacheTicker(f.conntrackCacheTimeout)
	ad, _ := f.writers[0].LocalAddr()

	for {
		p := <-u.rxPackets
		ua.Port = p.Port
		ua.IP = p.IP
		l.Error("GOT A PACKET FROM ", ua, " on ", ad)
		f.readOutsidePackets(ua, plaintext, p.Data, header, fwPacket, lhh, nb, q, conntrackCache.Get())
	}
}

func (u *udpConn) reloadConfig(*Config) {}

func NewUDPStatsEmitter([]*udpConn) func() {
	// No UDP stats for non-linux
	return func() {}
}

func (u *udpConn) LocalAddr() (*udpAddr, error) {
	return u.addr, nil
}

func (u *udpConn) Rebind() error {
	return nil
}

func hostDidRoam(addr *udpAddr, newaddr *udpAddr) bool {
	return !addr.Equals(newaddr)
}
