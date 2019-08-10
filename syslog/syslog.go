package syslog

import(
	"fmt"
	"os"
)

type Syslog struct {
	debug bool
}

func (s *Syslog) Error(msg string) {
	if s.debug == true {
		fmt.Fprintf(os.Stderr, msg)
	}
}

func New(debug bool) *Syslog {
	syslog := new(Syslog)
	syslog.debug = debug
	return syslog
}
