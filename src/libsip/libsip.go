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
	dialogs  cmap.ConcurrentMap //map[callid]*dialog  只有invite和subscribe请求会触发dialog
	requests cmap.ConcurrentMap //map[requestID]*ServerTransaction 记录客户端的请求所对应的服务端事务，便于响应
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
		ua.dialogs = nil //todo clear dialog
	}
}

//发送请求到服务端,注册ResponseHandler处理收到的响应
func (uac *SipUA) SendRequest(requestID string, method Method, requestURI *URI, msg *Message) error {

	headers, err := uac.constructRequestHeader(method, msg)
	if err != nil {
		return err
	}
	request := base.NewRequest(
		base.Method(method),
		&base.SipUri{
			User: base.String{S: requestURI.User},
			Host: requestURI.Host,
			Port: &requestURI.Port,
		},
		"SIP/2.0",
		headers,
		msg.Body,
	)

	log.Info("Sending: %v", request.Short())
	tx := uac.tm.Send(request, fmt.Sprintf("%v:%v", requestURI.Host, requestURI.Port))
	for {
		select {
		case r := <-tx.Responses():
			log.Info("Received response: %v", r.Short())

			tag, ok := r.Headers("To")[0].(*base.ToHeader).Params.Get("tag")
			if ok {
				switch str := tag.(type) {
				case base.String:
					if temp, ok := uac.dialogs.Get(string(r.Headers("Call-Id")[0].(*base.CallId))); ok {
						dia := temp.(&dialog)
						dia.to_tag = str.S
					}
				}
			}

			if method.Equals(INVITE) {
				// Ack 200s manually.
				log.Info("Sending Ack")
				tx.Ack()
			}
			if uac.ResponseHandler != nil {
				smsg, _ := uac.buildMessage(r)
				go uac.ResponseHandler(requestID, r.StatusCode, method, smsg)
			}
		case e := <-tx.Errors():
			log.Warn(e.Error())
			uac.clearDialog(msg.Header.CallId) //invite和subscribe请求不成功
			return e
		}
	}
	return nil
}

//处理客户端发送的请求，注册RequestHandler处理收到的请求
func (uas *SipUA) ServeResponse(requestID string, statusCode uint16, method Method, message *Message) error {
	tx, OK := uas.requests.Pop(requestID)
	if OK {
		stx := tx.(*transaction.ServerTransaction)
		reason := getReason(statusCode)

		headers, err := uas.constructResponseHeader(stx, message);
		if err != nil {
			return fmt.Errorf("Message Error,Message headers %v cannot convert to correct underling sipmessage headers.", message.Header)
		}
		log.Info("Sending Response.")
		resp := base.NewResponse(
			"SIP/2.0",
			statusCode,
			reason,
			headers,
			message.Body,
		)
		stx.Respond(resp)
		return nil
	}
	return fmt.Errorf("The request %v dos not exist.", requestID)

}
func (ua *SipUA) constructResponseHeader(stx *transaction.ServerTransaction, msg *Message) ([]base.SipHeader, error) {

	fromTag, toTag := "", ""
	tag, _ := stx.Origin().Headers("From")[0].(*base.FromHeader).Params.Get("tag")
	if tag != nil {
		fromTag = fmt.Sprintf("v", tag)
	}
	tag, _ = stx.Origin().Headers("To")[0].(*base.ToHeader).Params.Get("tag")
	if tag != nil {
		toTag = fmt.Sprintf("v", tag)
	} else {
		toTag = rand.RandomAlphanumeric(10)
	}
	vias := stx.Origin().Headers("Via")
	headers := []base.SipHeader{
		From(msg.Header.From, fromTag),
		To(msg.Header.To, toTag),
		CallId(msg.Header.CallId),
		CSeq(stx.Origin().Headers("CSeq")[0].(*base.CSeq).SeqNo, stx.Origin().Method),
	}
	headers = append(headers, vias...)

	//if msg.Header.Contact != nil {
	//	headers = append(headers, Contact(msg.Header.Contact))
	//}
	contactHeader := Contact(msg.Header.Contact, nil)
	if string(stx.Origin().Method) != "REGISTER" { //register 在下面特殊处理
		headers = append(headers, contactHeader)
	}
	switch string(stx.Origin().Method) {
	case "REGISTER":
		if len(msg.Header.WWWAuthenticate) > 0 {
			headers = append(headers, WWWAuthenticate(msg.Header.WWWAuthenticate))
		} else {
			//todo 刷新注册频繁如何处理
			ex := msg.Header.Expires / 3
			headers = append(headers, Contact(msg.Header.Contact, &ex))
		}
	case "MESSAGE":
		headers = append(headers, ContentType("application/xml"))
	case "INVITE":
		headers = append(headers, ContentType("application/SDP"))
	case "SUBSCRIBE":
		//todo 订阅响应过期时间
		headers = append(headers, Expires(msg.Header.Expires))
	}
	headers = append(headers, ContentLength(uint32(len(msg.Body))))

	return headers, nil
}
func (uac *SipUA) constructRequestHeader(method Method, msg *Message) ([]base.SipHeader, error) {

	dia := uac.getDialog(method, msg)
	//公共部分
	headers := []base.SipHeader{
		From(msg.Header.From, dia.from_tag),
		To(msg.Header.To, dia.to_tag),
		Via(msg.Header.Via, dia.currentTx.branch),
		CallId(msg.Header.CallId),
		CSeq(dia.cseq, base.Method(method)),
	}
	if !method.Equals(REGISTER) {
		headers = append(headers, Contact(msg.Header.Contact, nil))
	}
	switch method {
	case REGISTER:
		if msg.Header.Expires == 0 { //注销
			headers = append(headers, Contact(msg.Header.Contact, &msg.Header.Expires))
		} else {
			headers = append(headers, Contact(msg.Header.Contact, nil))
			headers = append(headers, Expires(msg.Header.Expires))
		}
		if len(msg.Header.Authorization) > 0 {
			headers = append(headers, Authorization(msg.Header.Authorization)) //鉴权注册
		}
	case MESSAGE:
		headers = append(headers, ContentType(" application/xml"))
	case INVITE:
		headers = append(headers, ContentType("application/SDP"))
	case SUBSCRIBE:
		headers = append(headers,
			Event(msg.Header.Event),
			Expires(msg.Header.Expires),
			MaxForwards(70),
			ContentType("application/xml"))
	case NOTIFY:
		headers = append(headers, ContentType(" application/xml"))
		if msg.Header.Event != "" { //告警订阅通知,资源上报不需要
			headers = append(headers,
				Event(msg.Header.Event),
				SubscriptionState(msg.Header.SubscriptionState))
		}
	}
	headers = append(headers, ContentLength(uint32(len(msg.Body))))

	return headers, nil
}

func (ua *SipUA) getDialog(method Method, msg *Message) *dialog {
	dia := &dialog{}
	if temp, ok := ua.dialogs.Get(msg.Header.CallId); ok {
		dia = temp.(&dialog)
		dia.cseq += 1
	} else {
		dia.callId = msg.Header.CallId
		dia.from_tag = rand.RandomAlphanumeric(10)
		dia.to_tag = ""
		dia.cseq = 1
		dia.currentTx = txInfo{}
		dia.currentTx.branch = "z9hG4bK" + rand.RandomAlphabetic(10)
		switch method {
		case INVITE:
			ua.dialogs.Set(msg.Header.CallId, dia)
		case SUBSCRIBE:
			ua.dialogs.Set(msg.Header.CallId, dia)
			if msg.Header.Expires == 0 {
				ua.clearDialog(msg.Header.CallId)
			}
		case BYE:
			ua.clearDialog(msg.Header.CallId)
		}
	}
	return dia
}

func (ua *SipUA) clearDialog(callid string) {
	ua.dialogs.Pop(callid)
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
	if uas.RequestHandler != nil {
		if err := uas.RequestHandler(requestID, Method(r.Method), msg); err != nil {
			uas.errResponse(tx, err)
			return
		}
		uas.requests.Set(requestID, tx)
	} else {
		log.Warn("RequestHandler dos not exist.")
		return
	}

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

func (ua *SipUA) buildMessage(message base.SipMessage) (m *Message, e error) {
	msg := &Message{}

	defer func() {
		if err := recover(); err != nil {
			log.Warn("Request SipMessage Error: %v", msg)
			m = nil
			e = fmt.Errorf("Sip Message Error: %v", err)
		}
	}()

	fromURI := message.Headers("From")[0].(*base.FromHeader).Address.(*base.SipUri)
	msg.Header.From = &URI{fromURI.User.(base.String).S, fromURI.Host, *fromURI.Port }
	toURI := message.Headers("To")[0].(*base.ToHeader).Address.(*base.SipUri)
	msg.Header.To = &URI{toURI.User.(base.String).S, toURI.Host, *toURI.Port}
	contactURI := message.Headers("Contact")[0].(*base.ContactHeader).Address.(*base.SipUri)
	msg.Header.Contact = &URI{contactURI.User.(base.String).S, contactURI.Host, *contactURI.Port}
	msg.Header.Via = &URI{"", (*message.Headers("Via")[0].(*base.ViaHeader))[0].Host, *(*message.Headers("Via")[0].(*base.ViaHeader))[0].Port}
	msg.Header.CallId = string(*message.Headers("Call-Id")[0].(*base.CallId))
	//msg.Header.CSeq = message.Headers("CSeq")[0].(*base.CSeq).SeqNo
	msg.Header.ContentLength = uint32(*message.Headers("Content-Length")[0].(*base.ContentLength))

	if len(message.Headers("Content-type")) > 0 {
		msg.Header.ContentType = message.Headers("Content-type")[0].(*base.GenericHeader).Contents
	}

	//if len(message.Headers("MaxForwards")) > 0 {
	//	msg.Header.MaxForwards = uint32(*message.Headers("MaxForwards")[0].(*base.MaxForwards))
	//}

	if len(message.Headers("Expires")) > 0 {
		expires, _ := strconv.Atoi(message.Headers("Expires")[0].(*base.GenericHeader).Contents)
		msg.Header.Expires = uint32(expires)
	}
	if len(message.Headers("Event")) > 0 {
		msg.Header.Event = message.Headers("Event")[0].(*base.GenericHeader).Contents
	}
	if len(message.Headers("Subscription-State")) > 0 {
		msg.Header.SubscriptionState = message.Headers("Subscription-State")[0].(*base.GenericHeader).Contents
	}
	if len(message.Headers("WWW-Authenticate")) > 0 {
		msg.Header.WWWAuthenticate = message.Headers("WWW-Authenticate")[0].(*base.GenericHeader).Contents
	}
	if len(message.Headers("Authorization")) > 0 {
		msg.Header.Authorization = message.Headers("Authorization")[0].(*base.GenericHeader).Contents
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

func getReason(statusCode uint16) string {
	reason := "OK"
	switch {
	case statusCode < 200:
		reason = "Trying"
	case statusCode >= 200 && statusCode < 299:
		reason = "OK"
	case statusCode == 400:
		reason = "The request message is wrong"
	case statusCode == 401:
		reason = "Unauthorized"
	case statusCode == 403:
		reason = "Have no privilege for this operation"
	case statusCode == 404:
		reason = "The request object is not exist"
	case statusCode == 480:
		reason = "The PTZ has been controled by higher privilege user"
	case statusCode == 481:
		reason = "The session dose not exist"
	case statusCode == 500:
		reason = "Server error,cannot provide service"
	case statusCode == 503:
		reason = "Server payload is full"
	default:
		reason = "Unknown Error"

	}
	return reason
}
