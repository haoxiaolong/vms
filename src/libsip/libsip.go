package libsip

import (
	"github.com/stefankopieczek/gossip/transaction"
	"github.com/stefankopieczek/gossip/transport"
	"fmt"
	"libutil/cmap"
	"github.com/stefankopieczek/gossip/log"
	"github.com/stefankopieczek/gossip/base"
	"strconv"
	"libutil/rand"
	"time"
)

//UAC收到UAS的处理接口
type ResponseHandler func(requestID string, statusCode uint16, method Method, serverResponseMessage *Message) error

//UAS收到UAC的处理接口
type RequestHandler func(requestID string, method Method, clientRequestMessage *Message) error

//使用流程
//1.初始化
//2.Start
//3.注册Handler
//4.UA 收到Request->调用RequestHandler->业务处理->调用ServeResponse
//  UA 调用SendRequest->收到Reponse->调用ResponseHandler->业务处理->继续请求
//4.Stop
type SipUA struct {
	DisplayName string
	UserName    string

	Host            string
	Port            uint16 // Listens on this Port.
	Transport       string // Sends using this Transport. ("tcp" or "udp")
	RequestHandler  RequestHandler
	ResponseHandler ResponseHandler

	tm       *transaction.Manager
	dialogs  cmap.ConcurrentMap //map[string]*dialog
	requests cmap.ConcurrentMap
}

type dialog struct {
	callId    string
	to_tag    string // The tag in the To header.
	from_tag  string // The tag in the From header.
	currentTx txInfo // The current transaction.
	cseq      uint32
}

type txInfo struct {
	tx     transaction.Transaction // The underlying transaction.
	branch string                  // The via branch.
}

func (ua *SipUA) Start() error {

	trm, err := transport.NewManager(ua.Transport)
	if err != nil {
		return err
	}
	tm, err := transaction.NewManager(trm, fmt.Sprintf("%v:%v", ua.Host, ua.Port))
	if err != nil {
		return err
	}

	ua.tm = tm
	ua.dialogs = cmap.New()
	ua.requests = cmap.New()

	ua.processRequest()
	return nil

}

func (ua *SipUA) Stop() {
	if ua.tm != nil {
		ua.tm.Stop()
		ua.dialogs = nil
	}
}

//发送请求到服务端,注册ResponseHandler处理收到的响应
func (uac *SipUA) SendRequest(requestID string, method Method, requestURI string, message *Message) error {

	return nil
}

//处理客户端发送的请求，注册RequestHandler处理收到的请求
func (uas *SipUA) ServeResponse(requestID string, statusCode uint32, method Method, message *Message) error {
	tx, OK := uas.requests.Pop(requestID)
	if OK {
		stx := tx.(*transaction.ServerTransaction)



	}

}

//处理服务端收到的所有请求
func (uas *SipUA) processRequest() {
	log.Info("Listening for incoming requests...")
	go func() {
		for msg := range uas.tm.Requests() {
			go uas.handleClientRequest(msg)
		}
	}()
}

//解析收到的请求，将请求给业务层处理
func (uas *SipUA) handleClientRequest(tx *transaction.ServerTransaction) {
	r := tx.Origin()
	log.Info("Received request: %v", r.Short())
	msg, err := uas.buildMessage(r)
	if err != nil {
		uas.errResponse(tx, err)
		return
	}
	requestID := rand.RandomAlphanumeric(10)
	if err := uas.RequestHandler(requestID, Method(r.Method), msg); err != nil {
		uas.errResponse(tx, err)
		return
	}
	uas.requests.Set(requestID, tx)

	//如果视频Invite请求，等待200 OK 并将结果告知业务层
	//等待超时10s
	if tx.Origin().Method == base.INVITE {
		select {
		case ack := <-tx.Ack():
			ackMsg, _ := uas.buildMessage(ack)
			uas.RequestHandler(requestID, Method(ack.Method), ackMsg)
		case <-time.After(time.Second * 10):
			log.Warn("SipMessage %v ACK Timeout!", msg)
			uas.RequestHandler(requestID, ACK, nil)
		}

	}
}

func (ua *SipUA) buildMessage(request *base.Request) (m *Message, e error) {
	msg := &Message{}

	defer func() {
		if err := recover(); err != nil {
			log.Warn("Request SipMessage Error: %v", msg)
			m = nil
			e = fmt.Errorf("Sip Message Error: %v", err)
		}
	}()

	fromURI := request.Headers("From")[0].(*base.FromHeader).Address.(*base.SipUri)
	msg.Header.From = &URI{fromURI.User.(base.String).S, fromURI.Host, *fromURI.Port }
	toURI := request.Headers("To")[0].(*base.ToHeader).Address.(*base.SipUri)
	msg.Header.To = &URI{toURI.User.(base.String).S, toURI.Host, *toURI.Port}
	contactURI := request.Headers("Contact")[0].(*base.ContactHeader).Address.(*base.SipUri)
	msg.Header.Contact = &URI{contactURI.User.(base.String).S, contactURI.Host, *contactURI.Port}
	msg.Header.Via = &URI{"", (*request.Headers("Via")[0].(*base.ViaHeader))[0].Host, *(*request.Headers("Via")[0].(*base.ViaHeader))[0].Port}
	msg.Header.CallId = string(*request.Headers("Call-Id")[0].(*base.CallId))
	msg.Header.CSeq = request.Headers("CSeq")[0].(*base.CSeq).SeqNo
	msg.Header.ContentLength = uint32(*request.Headers("Content-Length")[0].(*base.ContentLength))

	if len(request.Headers("MaxForwards")) > 0 {
		msg.Header.MaxForwards = uint32(*request.Headers("MaxForwards")[0].(*base.MaxForwards))
	}

	if len(request.Headers("Expires")) > 0 {
		expires, _ := strconv.Atoi(request.Headers("Expires")[0].(*base.GenericHeader).Contents)
		msg.Header.Expires = uint32(expires)
	}
	if len(request.Headers("Event")) > 0 {
		msg.Header.Event = request.Headers("Event")[0].(*base.GenericHeader).Contents
	}
	if len(request.Headers("Subscription-State")) > 0 {
		msg.Header.SubscriptionState = request.Headers("Subscription-State")[0].(*base.GenericHeader).Contents
	}
	if len(request.Headers("WWW-Authenticate")) > 0 {
		msg.Header.Authorization = request.Headers("WWW-Authenticate")[0].(*base.GenericHeader).Contents
	}
	return msg, nil
}

func (uas *SipUA) errResponse(tx *transaction.ServerTransaction, err error) {
	resp := base.NewResponse(
		"SIP/2.0",
		400,
		"Bad Request",
		[]base.SipHeader{},
		err.Error(),
	)
	base.CopyHeaders("Via", tx.Origin(), resp)
	base.CopyHeaders("From", tx.Origin(), resp)
	base.CopyHeaders("To", tx.Origin(), resp)
	base.CopyHeaders("Call-Id", tx.Origin(), resp)
	base.CopyHeaders("CSeq", tx.Origin(), resp)
	resp.AddHeader(
		&base.ContactHeader{
			DisplayName: base.String{S: uas.DisplayName},
			Address: &base.SipUri{
				User: base.String{S: uas.UserName},
				Host: uas.Host,
			},
		},
	)
	tx.Respond(resp)
}
