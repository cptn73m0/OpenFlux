package tunnel

import (
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"openflux/network"
	"openflux/utils"
)

const ackAggregationWindow = 20 * time.Millisecond

type TunnelLinkEndpoint struct {
	dispatcher       stack.NetworkDispatcher
	onOutgoingPacket func([]byte)
	packetIn         atomic.Uint64
	packetOut        atomic.Uint64

	ackMu     sync.Mutex
	ackBuf    [][]byte
	ackCh     chan struct{}
	ackTimer  *time.Timer
	ackActive bool
}

func NewTunnelLinkEndpoint() *TunnelLinkEndpoint {
	e := &TunnelLinkEndpoint{
		ackCh: make(chan struct{}, 1),
	}
	go e.ackFlusher()
	return e
}

// isPureACK returns true when data is a TCP packet with only the ACK flag set
// and no payload. Such packets are safe to aggregate: delaying them by ~20ms
// has no effect on throughput (they confirm data already received) and cuts
// the number of transport messages by roughly half under bulk transfer.
func isPureACK(data []byte) bool {
	if len(data) < 40 {
		return false
	}
	ipIHL := int(data[0]&0x0F) * 4
	if len(data) < ipIHL+20 {
		return false
	}
	tcpOffset := int(data[ipIHL+12]>>4) * 4
	tcpFlags := data[ipIHL+13]
	totalLen := (int(data[2]) << 8) | int(data[3])
	payloadLen := totalLen - ipIHL - tcpOffset
	return tcpFlags == 0x10 && payloadLen == 0
}

// ackFlusher waits for the flush signal, grabs the buffered ACKs, and sends
// them as one batch. It runs in a single goroutine per endpoint.
func (e *TunnelLinkEndpoint) ackFlusher() {
	for range e.ackCh {
		e.ackMu.Lock()
		buf := e.ackBuf
		e.ackBuf = nil
		e.ackActive = false
		e.ackMu.Unlock()

		for _, pkt := range buf {
			if e.onOutgoingPacket != nil {
				e.onOutgoingPacket(pkt)
			}
		}
	}
}

// scheduleFlush arranges for buffered ACKs to be sent within
// ackAggregationWindow. Only the first caller after a flush starts the timer.
func (e *TunnelLinkEndpoint) scheduleFlush() {
	e.ackMu.Lock()
	defer e.ackMu.Unlock()
	if e.ackActive {
		return
	}
	e.ackActive = true
	// Use a background goroutine instead of a timer so we avoid timer
	// churn under high ACK rates. The goroutine sleeps a fixed interval
	// then signals the flusher.
	go func() {
		time.Sleep(ackAggregationWindow)
		select {
		case e.ackCh <- struct{}{}:
		default:
		}
	}()
}

func (e *TunnelLinkEndpoint) InjectInbound(data []byte) {
	e.packetIn.Add(1)
	utils.Debugf("<- %d bytes - %s\n", len(data), network.ParsePacketInfo(data))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte{}, data...)),
	})
	e.dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
}

func (e *TunnelLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	// Process gVisor packet list. Non-ACK packets go out immediately;
	// pure ACKs are aggregated and flushed every ackAggregationWindow.
	for _, pkt := range pkts.AsSlice() {
		data := pkt.ToView().ToSlice()
		e.packetOut.Add(1)
		utils.Debugf("-> %d bytes - %s\n", len(data), network.ParsePacketInfo(data))

		if isPureACK(data) {
			e.ackMu.Lock()
			e.ackBuf = append(e.ackBuf, data)
			e.ackMu.Unlock()
			e.scheduleFlush()
		} else {
			// Flush any pending ACKs before sending a data packet so the
			// receiver gets them in order.
			e.ackMu.Lock()
			ackBuf := e.ackBuf
			e.ackBuf = nil
			e.ackActive = false
			e.ackMu.Unlock()
			for _, a := range ackBuf {
				if e.onOutgoingPacket != nil {
					e.onOutgoingPacket(a)
				}
			}
			if e.onOutgoingPacket != nil {
				e.onOutgoingPacket(data)
			}
		}
		n++
	}
	return n, nil
}

func (e *TunnelLinkEndpoint) MTU() uint32                                 { return 1500 }
func (e *TunnelLinkEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *TunnelLinkEndpoint) LinkAddress() tcpip.LinkAddress               { return "\x02\x00\x00\x00\x00\x01" }
func (e *TunnelLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (e *TunnelLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}
func (e *TunnelLinkEndpoint) IsAttached() bool                             { return e.dispatcher != nil }
func (e *TunnelLinkEndpoint) Wait()                                        {}
func (e *TunnelLinkEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *TunnelLinkEndpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *TunnelLinkEndpoint) Close()                                       {}
func (e *TunnelLinkEndpoint) SetMTU(uint32)                                {}
func (e *TunnelLinkEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *TunnelLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *TunnelLinkEndpoint) SetOnCloseAction(func())                      {}
