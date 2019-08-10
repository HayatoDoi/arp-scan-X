package syslog

import(
	"fmt"
	"os"
)

type Syslog struct {
	debug bool
}

func (s *Syslog) Debugln(format string, a ...interface{}) {
	if s.debug == true {
		fmt.Fprintf(os.Stdout, format+"\n", a...)
	}
}

func (s *Syslog) Errorln(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

func (s *Syslog) Println(format string, a ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func New(debug bool) *Syslog {
	syslog := new(Syslog)
	syslog.debug = debug
	return syslog
}
