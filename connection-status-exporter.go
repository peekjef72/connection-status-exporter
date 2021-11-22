// Copyright 2019 David de Torres
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"
	"os"

	// "strings"

	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// Branch is set during build to the git branch.
var Branch string

// BuildDate is set during build to the ISO-8601 date and time.
var BuildDate string

// Revision is set during build to the git commit revision.
var Revision string

// Version is set during build to the git describe version
// (semantic version)-(commitish) form.
var Version = "0.1.1"

// VersionShort is set during build to the semantic version.
var VersionShort = "0.1.1"

const (

	// Prefix for Prometheus metrics
	namespace = "connection_status_up"

	// Constant values
	connectionOk          = 1
	connectionErr         = 0
	metricsPublishingPort = ":9293"
)

var (
	listenAddress = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(metricsPublishingPort).String()
	metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose collector's internal metrics.").Default("/metrics").String()
	configFile    = kingpin.Flag("config-file", "Exporter configuration file.").Default("config/config.yaml").String()

//	exportPath       = kingpin.Flag("web.export-path", "Path under which to expose targets' metrics.").Default("/export").String()
)

//***********************************************************************************************
func handler(w http.ResponseWriter, r *http.Request, exporter *SocketSetExporter) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(exporter)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

//***********************************************************************************************
func main() {
	var sockets *socketSet
	var err error

	logConfig := promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, &logConfig)
	kingpin.Version(version.Print("connection-status-exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// Setup build info metric.
	// version.Branch = Branch
	// version.BuildDate = BuildDate
	// version.Revision = Revision
	// version.Version = VersionShort

	logger := promlog.New(&logConfig)
	level.Info(logger).Log("msg", "Starting connection-status-exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	// read the configuration if not empty
	if *configFile != "" {
		sockets, err = Load(*configFile)
		if err != nil {
			level.Error(logger).Log("Errmsg", "Error loading config", "err", err)
			os.Exit(1)
		}
	}
	// create a new exporter
	sockExporter := NewSocketSetExporter(sockets, logger)
	//	prometheus.MustRegister(sockExporter)
	level.Info(logger).Log("msg", "Connection Status Exporter initialized")

	var landingPage = []byte(`<html>
		<head>
		<title>Connection Status Exporter</title>
		</head>
		<body>
		<h1>Connection Status Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
		</body>
		</html>
	`)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8") // nolint: errcheck
		w.Write(landingPage)                                       // nolint: errcheck
	})

	http.HandleFunc(*metricsPath, func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, sockExporter)
	})

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server")
		os.Exit(1)
	}
}
