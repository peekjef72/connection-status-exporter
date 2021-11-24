package main

import (
	"fmt"
	"strings"

	"strconv"

	// "strings"
	"sync"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

// SocketSetExporter Exporter of the status of connection
type SocketSetExporter struct {
	socketStatusMetrics *prometheus.GaugeVec
	socketCountMetrics  *prometheus.GaugeVec
	mutex               sync.Mutex
	sockets             *socketSet
	logger              log.Logger
}

const (
	// Prefix for Prometheus metrics
	namespace = "connection_status_up"

	// Constant values
	connectionOk  = 1
	connectionErr = 0
)

var SocketSetLabels = []string{"name", "srchost", "srcport", "deshost", "destport", "protocol", "status", "process"}

// NewSocketSetExporter Creator of SocketSetExporter
func NewSocketSetExporter(sockets *socketSet, logger log.Logger) *SocketSetExporter {

	return &SocketSetExporter{
		socketStatusMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "connection_status_up",
				Help: "Connection status of the socket (0 down - 1 up).",
			}, SocketSetLabels),
		socketCountMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "connection_status_count",
				Help: "number of socket with same parameter.",
			}, SocketSetLabels),
		sockets: sockets,
		logger:  logger,
	}
}

// Describe Implements interface
func (exporter *SocketSetExporter) Describe(prometheusChannel chan<- *prometheus.Desc) {
	exporter.socketStatusMetrics.Describe(prometheusChannel)
	return
}

// Collect Implements interface
func (exporter *SocketSetExporter) Collect(prometheusChannel chan<- prometheus.Metric) {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()
	exporter.sockets.collect(exporter)
	exporter.socketStatusMetrics.Collect(prometheusChannel)
	exporter.socketCountMetrics.Collect(prometheusChannel)
	return
}

// Calls the method collect of each socket in the socketSet
func (thisSocketSet *socketSet) collect(exporter *SocketSetExporter) {

	for proto, sockets := range thisSocketSet.socksByType {
		var fn func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error)
		if proto == "tcp" {
			fn = netstat.TCPSocks
		} else if proto == "udp" {
			fn = netstat.UDPSocks
		} else if proto == "tcp6" {
			fn = netstat.TCP6Socks
		} else if proto == "udp6" {
			fn = netstat.UDP6Socks
		}
		entries, err := fn(netstat.NoopFilter)

		if err != nil {
			level.Error(exporter.logger).Log("msg", fmt.Sprintf("%+v", err))
		}

		for _, currentSocket := range sockets {
			currentSocket.collect(exporter, entries, proto)
		}

	}
	// if len(thisSocketSet.tcpSockets) > 0 {
	// 	entries, err := netstat.TCPSocks(netstat.NoopFilter)
	// 	if err != nil {
	// 		level.Error(exporter.logger).Log("msg", fmt.Sprintf("%+v", err))
	// 	}

	// 	for _, currentSocket := range thisSocketSet.tcpSockets {
	// 		currentSocket.collect(exporter, entries)
	// 	}
	// }
	// if len(thisSocketSet.udpSockets) > 0 {
	// 	entries, err := netstat.UDPSocks(netstat.NoopFilter)
	// 	if err != nil {
	// 		level.Error(exporter.logger).Log("msg", fmt.Sprintf("%+v", err))
	// 	}

	// 	for _, currentSocket := range thisSocketSet.udpSockets {
	// 		currentSocket.collect(exporter, entries)
	// 	}
	// }
	return
}

// Checks the status of the connection of a socket and updates it in the Metric
func (thisSocket *socket) collect(exporter *SocketSetExporter, entries []netstat.SockTabEntry, proto string) {
	connectionCount := 0

	for _, entry := range entries {
		// level.Debug(exporter.logger).Log("socket", fmt.Sprintf("%+v", entry))
		// level.Debug(exporter.logger).Log("addr", fmt.Sprintf("%s", entry.LocalAddr.IP.String()))
		if thisSocket.Status == "listen" && entry.State != netstat.Listen {
			continue
		}
		if thisSocket.Status == "established" && entry.State != netstat.Established {
			continue
		}
		if thisSocket.SrcHost != "" {
			if strings.EqualFold(thisSocket.SrcHost, "any") {
				if proto == "tcp6" || proto == "udp6" {
					if entry.LocalAddr.IP.String() != "::" {
						continue
					}
				} else {
					if entry.LocalAddr.IP.String() != "0.0.0.0" {
						continue
					}

				}
			} else if thisSocket.SrcHost != entry.LocalAddr.IP.String() {
				continue
			}
		}
		if thisSocket.DestHost != "" {
			if strings.EqualFold(thisSocket.DestHost, "any") {
				if proto == "tcp6" || proto == "udp6" {
					if entry.RemoteAddr.IP.String() != "::" {
						continue
					}
				} else {
					if entry.RemoteAddr.IP.String() != "0.0.0.0" {
						continue
					}

				}
			} else if thisSocket.DestHost != entry.RemoteAddr.IP.String() {
				continue
			}
		}
		if thisSocket.SrcPort != 0 && thisSocket.SrcPort != entry.LocalAddr.Port {
			continue
		}
		if thisSocket.DestPort != 0 && thisSocket.DestPort != entry.RemoteAddr.Port {
			continue
		}
		if thisSocket.ProcessName != "" && !thisSocket.procPattern.MatchString(entry.Process.Name) {
			continue
		}

		connectionCount++
		// break
	}
	labels := make([]string, len(SocketSetLabels))
	labels[0] = thisSocket.Name
	if thisSocket.SrcHost == "" {
		labels[1] = "*"
	} else {
		labels[1] = thisSocket.SrcHost
	}
	if thisSocket.SrcPort == 0 {
		labels[2] = "*"
	} else {
		labels[2] = strconv.Itoa(int(thisSocket.SrcPort))
	}
	if thisSocket.DestHost == "" {
		labels[3] = "*"
	} else {
		labels[3] = thisSocket.DestHost
	}
	if thisSocket.DestPort == 0 {
		labels[4] = "*"
	} else {
		labels[4] = strconv.Itoa(int(thisSocket.DestPort))
	}
	labels[5] = thisSocket.Protocol
	labels[6] = thisSocket.Status
	if thisSocket.ProcessName == "" {
		labels[7] = "*"
	} else {
		labels[7] = thisSocket.ProcessName
	}
	level.Debug(exporter.logger).Log("labels:", fmt.Sprintf("%+q", labels))

	// Updated the status of the socket in the metric
	exporter.socketStatusMetrics.WithLabelValues(labels[:]...).Set(float64(connectionCount))

	connectionStatus := 0
	if connectionCount > 0 {
		connectionStatus = 1
	}
	exporter.socketCountMetrics.WithLabelValues(labels[:]...).Set(float64(connectionStatus))

	return
}
