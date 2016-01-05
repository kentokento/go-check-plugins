package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/mackerelio/checkers"
)

var timeNow = time.Now()

var opts struct {
	Domain           string `short:"d" long:"domain" required:"true" description:"monitor domain name"`
	WarningDayCount  int    `short:"w" long:"warning" default:"30" description:"warning if once past the day"`
	CriticalDayCount int    `short:"c" long:"critical" default:"15" description:"critical if once past the day"`
}

func getCert(host string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", host+":443", nil)
	var peerCertificates []*x509.Certificate
	if err == nil {
		connectionState := conn.ConnectionState()
		peerCertificates = connectionState.PeerCertificates
	}
	return peerCertificates, err
}

func run(args []string) *checkers.Checker {
	_, err := flags.ParseArgs(&opts, args)
	if err != nil {
		os.Exit(1)
	}

	result := checkers.OK
	msg := ""

	peerCertificates, err := getCert(opts.Domain)
	if err != nil {
		return checkers.Unknown(err.Error())
	}
	for _, Cert := range peerCertificates {
		certNotAfter := Cert.NotAfter
		duration := certNotAfter.Sub(timeNow)
		diffDays := int(duration.Hours() / 24)
		if diffDays < opts.CriticalDayCount {
			msg = fmt.Sprintf("It is another %d days on the expiration date of the SSL certificate of %s.",
				diffDays, opts.Domain)
			result = checkers.CRITICAL
			break
		} else if diffDays < opts.WarningDayCount {
			msg = fmt.Sprintf("It is another %d days on the expiration date of the SSL certificate of %s.",
				diffDays, opts.Domain)
			result = checkers.WARNING
			break
		}
		if msg == "" {
			msg = fmt.Sprintf("It is another %d days on the expiration date of the SSL certificate of %s.",
				diffDays, opts.Domain)
		}
	}
	return checkers.NewChecker(result, msg)
}

func main() {
	ckr := run(os.Args[1:])
	ckr.Name = "Cert"
	ckr.Exit()
}
