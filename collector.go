package main

import (
	"fmt"

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
	mutex               sync.Mutex
	sockets             *socketSet
	logger              log.Logger
}

// NewSocketSetExporter Creator of SocketSetExporter
func NewSocketSetExporter(sockets *socketSet, logger log.Logger) *SocketSetExporter {

	return &SocketSetExporter{
		socketStatusMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: namespace,
				Help: "Connection status of the socket.",
			}, []string{"name", "srchost", "srcport", "deshost", "destport", "protocol", "status"}),
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
	return
}

// Calls the method collect of each socket in the socketSet
func (thisSocketSet *socketSet) collect(exporter *SocketSetExporter) {
	if len(thisSocketSet.tcpSockets) > 0 {
		entries, err := netstat.TCPSocks(netstat.NoopFilter)
		if err != nil {
			level.Error(exporter.logger).Log("msg", fmt.Sprintf("%+v", err))
		}

		for _, currentSocket := range thisSocketSet.tcpSockets {
			currentSocket.collect(exporter, entries)
		}
	}
	if len(thisSocketSet.udpSockets) > 0 {
		entries, err := netstat.UDPSocks(netstat.NoopFilter)
		if err != nil {
			level.Error(exporter.logger).Log("msg", fmt.Sprintf("%+v", err))
		}

		for _, currentSocket := range thisSocketSet.udpSockets {
			currentSocket.collect(exporter, entries)
		}
	}
	return
}

// Checks the status of the connection of a socket and updates it in the Metric
func (thisSocket *socket) collect(exporter *SocketSetExporter, entries []netstat.SockTabEntry) {
	connectionStatus := connectionErr

	for _, entry := range entries {
		if thisSocket.Status == "listen" && entry.State != netstat.Listen {
			continue
		}
		if thisSocket.Status == "established" && entry.State != netstat.Established {
			continue
		}
		if thisSocket.SrcHost != "" && thisSocket.SrcHost != entry.LocalAddr.IP.String() {
			continue
		}
		if thisSocket.DestHost != "" && thisSocket.DestHost != entry.RemoteAddr.IP.String() {
			continue
		}
		if thisSocket.SrcPort != 0 && thisSocket.SrcPort != entry.LocalAddr.Port {
			continue
		}
		if thisSocket.DestPort != 0 && thisSocket.DestPort != entry.RemoteAddr.Port {
			continue
		}
		connectionStatus = connectionOk
		level.Debug(exporter.logger).Log("socket:", fmt.Sprintf("%+v", entry))
		break
	}
	labels := make([]string, 7)
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
	level.Debug(exporter.logger).Log("labels:", fmt.Sprintf("%+q", labels))

	// Updated the status of the socket in the metric
	exporter.socketStatusMetrics.WithLabelValues(labels[:]...).Set(float64(connectionStatus))
	// thisSocket.Name,
	// thisSocket.Host,
	// strconv.Itoa(thisSocket.Port),
	// thisSocket.Protocol
	// ).Set(float64(connectionStatus))

	// If the socket was open correctly, close it
	// if connectionStatus == connectionOk {
	// 	err = connection.Close()
	// 	if err != nil {
	// 		level.Info(exporter.logger).Log("Error closing the socket")
	// 	}
	// }
	return
}
