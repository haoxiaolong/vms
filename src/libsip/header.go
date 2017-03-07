package libsip

import (
	"github.com/stefankopieczek/gossip/base"
	"strconv"
)

// Utility methods for creating headers.

func Via(e *SipUA, branch string) *base.ViaHeader {
	return &base.ViaHeader{
		&base.ViaHop{
			ProtocolName:    "SIP",
			ProtocolVersion: "2.0",
			Transport:       e.Transport,
			Host:            e.Host,
			Port:            &e.Port,
			Params:          base.NewParams().Add("branch", base.String{S: branch}),
		},
	}
}

func To(e *SipUA, tag string) *base.ToHeader {
	header := &base.ToHeader{
		DisplayName: base.String{S: e.DisplayName},
		Address: &base.SipUri{
			User:      base.String{S: e.UserName},
			Host:      e.Host,
			UriParams: base.NewParams(),
		},
		Params: base.NewParams(),
	}

	if tag != "" {
		header.Params.Add("tag", base.String{S: tag})
	}

	return header
}

func From(e *SipUA, tag string) *base.FromHeader {
	header := &base.FromHeader{
		DisplayName: base.String{S: e.DisplayName},
		Address: &base.SipUri{
			User:      base.String{S: e.UserName},
			Host:      e.Host,
			UriParams: base.NewParams().Add("Transport", base.String{S: e.Transport}),
		},
		Params: base.NewParams(),
	}

	if tag != "" {
		header.Params.Add("tag", base.String{S: tag})
	}

	return header
}

func Contact(e *SipUA) *base.ContactHeader {
	return &base.ContactHeader{
		DisplayName: base.String{S: e.DisplayName},
		Address: &base.SipUri{
			User: base.String{S: e.UserName},
			Host: e.Host,
		},
	}
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

func Authorization(a string) *base.GenericHeader {
	header := base.GenericHeader{HeaderName: "WWW-Authenticate", Contents: a}
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
