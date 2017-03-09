package libsip

import (
	"github.com/stefankopieczek/gossip/base"
	"strconv"
	"fmt"
)

// Utility methods for creating headers.

func Via(uri *URI, branch string) *base.ViaHeader {
	return &base.ViaHeader{
		&base.ViaHop{
			ProtocolName:    "SIP",
			ProtocolVersion: "2.0",
			Transport:       "UDP",
			Host:            uri.Host,
			Port:            &uri.Port,
			Params:          base.NewParams().Add("branch", base.String{S: branch}),
		},
	}
}

func To(uri *URI, tag string) *base.ToHeader {
	header := &base.ToHeader{
		Address: &base.SipUri{
			User:      base.String{S: uri.User},
			Host:      uri.Host,
			Port:      &uri.Port,
			UriParams: base.NewParams(),
		},
		Params: base.NewParams(),
	}

	if tag != "" {
		header.Params.Add("tag", base.String{S: tag})
	}

	return header
}

func From(uri *URI, tag string) *base.FromHeader {
	header := &base.FromHeader{
		Address: &base.SipUri{
			User:      base.String{S: uri.User},
			Host:      uri.Host,
			Port:      &uri.Port,
			UriParams: base.NewParams().Add("Transport", base.String{S: "UDP"}),
		},
		Params: base.NewParams(),
	}

	if tag != "" {
		header.Params.Add("tag", base.String{S: tag})
	}

	return header
}

func Contact(uri *URI, expires *uint32) *base.ContactHeader {
	header := &base.ContactHeader{
		Address: &base.SipUri{
			User: base.String{S: uri.User},
			Host: uri.Host,
			Port: &uri.Port,
		},
	}
	if expires != nil {
		header.Params.Add("expires", base.String{S: fmt.Sprintf("%v", *expires)})
	}

	return header
}

func CSeq(seqno uint32, method base.Method) *base.CSeq {
	return &base.CSeq{
		SeqNo:      seqno,
		MethodName: method,
	}
}

func CallId(callid string) *base.CallId {
	header := base.CallId(callid)
	return &header
}

func ContentLength(l uint32) base.ContentLength {
	return base.ContentLength(l)
}

func ContentType(ct string) *base.GenericHeader {
	header := base.GenericHeader{HeaderName: "Content-type", Contents: ct}
	return &header
}

func WWWAuthenticate(a string) *base.GenericHeader {
	header := base.GenericHeader{HeaderName: "WWW-Authenticate", Contents: a}
	return &header
}

func Authorization(a string) *base.GenericHeader {
	header := base.GenericHeader{HeaderName: "Authorization", Contents: a}
	return &header
}

func Expires(ms uint32) *base.GenericHeader {
	header := base.GenericHeader{HeaderName: "Expires", Contents: strconv.Itoa((int)(ms))}
	return &header
}

func Event(e string) *base.GenericHeader {
	header := base.GenericHeader{HeaderName: "Event", Contents: e}
	return &header
}
func SubscriptionState(s string) *base.GenericHeader {
	header := base.GenericHeader{HeaderName: "Subscription-State", Contents: s}
	return &header
}

func MaxForwards(f uint32) base.MaxForwards {
	return base.MaxForwards(f)
}
