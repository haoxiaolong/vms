package main

import (
	"fmt"
	"github.com/stefankopieczek/gossip/base"
	"libsip"
)

func main() {
	m := base.INVITE
	b := libsip.Method(m)

	defer recover()
	panic("aaabbb")
	fmt.Printf("%v", b)
}
