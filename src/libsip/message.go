package libsip

import (
	"strings"
	"fmt"
)

type Method string

func (method Method) Equals(other Method) bool {
	if method != "" && other != "" {
		return strings.EqualFold(string(method), string(other))
	} else {
		return method == other
	}
}

const (
	INVITE    Method = "INVITE"
	ACK       Method = "ACK"
	BYE       Method = "BYE"
	REGISTER  Method = "REGISTER"
	SUBSCRIBE Method = "SUBSCRIBE"
	NOTIFY    Method = "NOTIFY"
	MESSAGE   Method = "MESSAGE"
	INFO      Method = "INFO"
)

//简化，不使用Map
//所有字段只包含SIP协议中的值，不好含属性，如<sip:前端系统地址编码@前端系统所属平台域名或 IP 地址>;tag=h7g4E，不包含tag
type Header struct {
	From    *URI
	To      *URI
	Via     *URI
	Contact *URI
	CallId  string
	//CSeq    uint32

	ContentType   string
	ContentLength uint32

	WWWAuthenticate   string
	Authorization     string
	Expires           uint32
	Event             string
	SubscriptionState string

	//MaxForwards uint32
}
type URI struct {
	User string
	Host string
	Port uint16
}

func (uri *URI) String() string {
	return fmt.Sprintf("%v@%v:%d", uri.User, uri.Host, uri.Port)
}

type Message struct {
	Header Header
	Body   string
}
