package main

import (
	"fmt"
	"io/ioutil"
	"strings"

	"gopkg.in/yaml.v2"
)

type socketSet struct {
	Sockets []socket `yalm:"sockets"`

	// Catches all undefined fields and must be empty after parsing.
	XXX map[string]interface{} `yaml:",inline" json:"-"`

	tcpSockets []socket
	udpSockets []socket
}

type socket struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host,omitempty"`
	SrcHost  string `yaml:"srcHost,omitempty"`
	DestHost string `yaml:"destHost,omitempty"`
	Port     uint16 `yaml:"port,omitempty"`
	SrcPort  uint16 `yaml:"srcPort,omitempty"`
	DestPort uint16 `yaml:"destPort,omitempty"`
	Protocol string `yaml:"protocol,omitempty"`

	Status string `yaml:"status,omitempty"`
}

const (
	// Default values for optional parameters of socket
	defaultProtocol string = "tcp"

	// Default values for optional parameters of socket
	defaultStatus string = "listen"
)

// *************************************************************
//
// *************************************************************
// Load attempts to parse the given config file and return a Config object.
func Load(configFile string) (*socketSet, error) {
	//	log.Infof("Loading profiles from %s", profilesFile)
	buf, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	sockets := socketSet{}
	err = yaml.Unmarshal(buf, &sockets)
	if err != nil {
		return nil, err
	}
	err = checkOverflow(sockets.XXX, "sockets")
	if err != nil {
		return nil, err
	}

	err = sockets.check()
	if err != nil {
		return nil, err
	}

	sockets.tcpSockets = sockets.getSocketProtocol("tcp")
	sockets.udpSockets = sockets.getSocketProtocol("udp")

	return &sockets, nil
}

// *************************************************************
//
// socketSet
//
// *************************************************************
// check the sanity of the sockets in the set
func (thisSocketSet *socketSet) check() error {
	for index := range thisSocketSet.Sockets {
		err := thisSocketSet.Sockets[index].check()
		if err != nil {
			return (err)
		}
	}
	return (nil)
}

// collect slice of sockets for a specific protocol
func (thisSocketSet *socketSet) getSocketProtocol(protocol string) []socket {
	list := make([]socket, 0)
	for index := range thisSocketSet.Sockets {
		if thisSocketSet.Sockets[index].Protocol == protocol {
			list = append(list, thisSocketSet.Sockets[index])
		}
	}
	return list
}

// *************************************************************
//
// socket
//
// *************************************************************
// Check the sanity of the socket and fills the default values
func (thisSocket *socket) check() error {
	if thisSocket.Name == "" {
		return (fmt.Errorf("socket must have the field name set"))
	}
	if thisSocket.Status == "" {
		thisSocket.Status = defaultStatus
	}
	// Check if the protocol is among the valid ones
	if IsValidStatus(thisSocket.Status) == false {
		return (fmt.Errorf("The status of the socket is not a valid one"))
	}

	if thisSocket.Status == "listen" {
		if thisSocket.SrcHost == "" && thisSocket.Host == "" {
			return (fmt.Errorf("socket must have the field host or srcHost set"))
		}
		if thisSocket.Port == 0 && thisSocket.SrcPort == 0 {
			return (fmt.Errorf("socket must have the field port or srcPort"))
		}
	} else {
		if thisSocket.SrcHost == "" && thisSocket.Host == "" && thisSocket.DestHost == "" {
			return (fmt.Errorf("socket must have the field host or srcHost or dstHost set"))
		}

		if thisSocket.Port == 0 && thisSocket.SrcPort == 0 && thisSocket.DestPort == 0 {
			return (fmt.Errorf("socket must have the field port or srcPort or dstPort set"))
		}
	}

	if thisSocket.SrcHost == "" {
		thisSocket.SrcHost = thisSocket.Host
	}

	if thisSocket.SrcPort == 0 {
		thisSocket.SrcPort = thisSocket.Port
	}

	if thisSocket.Protocol == "" {
		thisSocket.Protocol = defaultProtocol
	}

	// Check if the protocol is among the valid ones
	if IsValidProtocol(thisSocket.Protocol) == false {
		return (fmt.Errorf("The protocol of the socket is not a valid one"))
	}
	return (nil)
}

// IsValidProtocol Check if a string is among the valid protocols
func IsValidProtocol(protocol string) bool {
	switch protocol {
	case
		"tcp",
		"tcp4",
		"tcp6",
		"udp",
		"udp4",
		"udp6":
		// "ip",
		// "ip4",
		// "ip6",
		// "unix",
		// "unixgram",
		// "unixpacket":
		return true
	}
	return false
}

// IsValidProtocol Check if a string is among the valid protocols
func IsValidStatus(status string) bool {
	switch status {
	case
		"listen",
		"established":
		return true
	}
	return false
}

// to catch unwanted params in config file
func checkOverflow(m map[string]interface{}, ctx string) error {
	if len(m) > 0 {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		return fmt.Errorf("unknown fields in %s: %s", ctx, strings.Join(keys, ", "))
	}
	return nil
}
