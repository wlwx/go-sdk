package sms

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type SmsMsgFmt int

const (
	SmsMsgAscii     SmsMsgFmt = 0
	SmsMsgWriteCard SmsMsgFmt = 3
	SmsMsgBinary    SmsMsgFmt = 4
	SmsMsgUCS2      SmsMsgFmt = 8

	sendMsgPath      = "/sendsms"
	sendVariantPath  = "/sendVariantSms"
	getTokenPath     = "/getToken"
	getMOPath        = "/getMO"
	getReport        = "/getReport"
	queryAccountPath = "/QueryAccount"
)

var sms_format_validate map[SmsMsgFmt]string = map[SmsMsgFmt]string{
	SmsMsgAscii:     "0",
	SmsMsgWriteCard: "3",
	SmsMsgBinary:    "4",
	SmsMsgUCS2:      "8",
}

type (
	SmsReq struct {
		Content     string
		DestMobiles string
		Uid         string
		NeedReport  bool
		MsgFmt      SmsMsgFmt
		SpCode      string
	}

	SmsVariantReq struct {
		CustCode   string        `json:"cust_code"`
		Content    string        `json:"content"`
		Params     []*MobileVars `json:"params"`
		Sign       string        `json:"sign"`
		SpCode     string        `json:"sp_code,omitempty"`
		Uid        string        `json:"uid,omitempty"`
		NeedReport string        `json:"need_report,omitempty"`
		MsgFmt     string        `json:"msgFmt,omitempty"`
	}

	SmsVeriantInput struct {
		Content     string
		DestMobiles string
		Uid         string
		NeedReport  bool
		MsgFmt      SmsMsgFmt
		SpCode      string
		Params      []*MobileVars
	}

	MobileVars struct {
		Mobile string   `json:"mobile"`
		Vars   []string `json:"vars"`
	}

	smsSendReq struct {
		CustCode    string `json:"cust_code"`
		Sign        string `json:"sign"`
		Content     string `json:"content"`
		DestMobiles string `json:"destMobiles"`
		Uid         string `json:"uid,omitempty"`
		NeedReport  string `json:"need_report,omitempty"`
		MsgFmt      string `json:"msgFmt,omitempty"`
		SpCode      string `json:"sp_code,omitempty"`
	}

	tokenReq struct {
		CustCode string `json:"cust_code"`
	}

	moReq struct {
		CustCode string `json:"cust_code"`
		TokenId  string `json:"token_id"`
		Sign     string `json:"sign"`
	}

	MOResult struct {
		SmsLabel   string `json:"smsLabel"`
		RecvTime   string `json:"recv_time"`
		MsgContent string `json:"msg_content"`
		SpCode     string `json:"sp_code"`
		SrcMobile  string `json:"src_mobile"`
		MsgId      string `json:"msg_id"`
	}

	ReportResult struct {
		MsgId        string `json:"msgid"`
		Mobile       string `json:"mobile"`
		ReportStatus string `json:"report_status"`
		Report       string `json:"report"`
		Uid          string `json:"uid"`
		RecvTime     string `json:"recv_time"`
	}

	AccountResult struct {
		CustCode   string `json:"cust_code"`
		Status     string `json:"status"`
		SmsBalance int    `json:"sms_balance"`
	}

	SmsResult struct {
		MsgId     string `json:"msgid"`
		Mobile    string `json:"mobile"`
		Code      string `json:"code"`
		Msg       string `json:"msg"`
		ChargeNum int    `json:"chargeNum"`
	}

	SmsRsp struct {
		Uid            string       `json:"uid"`
		Status         string       `json:"status"`
		RespCode       string       `json:"respCode"`
		RespMsg        string       `json:"respMsg"`
		TotalChargeNum int          `json:"totalChargeNum"`
		Result         []*SmsResult `json:"result"`
	}

	TokenRsp struct {
		TokenId string `json:"token_id"`
		Token   string `json:"token"`
	}

	SmsClient struct {
		addr       string
		custCode   string
		custPwd    string
		httpClient *http.Client
	}
)

func (w *SmsClient) defaultSmsRsp() *SmsRsp {
	return &SmsRsp{
		RespCode:       "-1",
		TotalChargeNum: 0,
	}
}

func (w *SmsClient) defaultTokenRsp() *TokenRsp {
	return &TokenRsp{
		TokenId: "",
		Token:   "",
	}
}

func NewSmsClient(addr, custCode, custPwd string) *SmsClient {
	return &SmsClient{
		addr:     addr,
		custCode: custCode,
		custPwd:  custPwd,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (w *SmsClient) checkReq(req *SmsReq) error {
	if len(req.Content) == 0 {
		return fmt.Errorf("Content cannot be empty.")
	}

	if len(req.DestMobiles) == 0 {
		return fmt.Errorf("DestMobiles cannot be empty.")
	}

	if len(req.Uid) > 20 {
		return fmt.Errorf("Uid length should not large than 20.")
	}

	return nil
}

func (w *SmsClient) GetToken() (*TokenRsp, error) {
	tokenReq := &tokenReq{
		CustCode: w.custCode,
	}
	req_data, err := json.Marshal(tokenReq)
	resp_bytes, err := w.doPost(getTokenPath, req_data)
	if err != nil {
		return nil, err
	}
	token_rsp := w.defaultTokenRsp()
	err = json.Unmarshal(resp_bytes, token_rsp)
	if err != nil {
		return nil, err
	}
	return token_rsp, nil
}

func (w *SmsClient) GetMO() ([]*MOResult, error) {
	tokenRsp, err := w.GetToken()
	if err != nil {
		return nil, err
	}
	tmp_sign := tokenRsp.Token + w.custPwd
	md5sign := md5.Sum([]byte(tmp_sign))
	tokenReq := &moReq{
		CustCode: w.custCode,
		TokenId:  tokenRsp.TokenId,
		Sign:     fmt.Sprintf("%x", md5sign),
	}
	req_data, err := json.Marshal(tokenReq)
	resp_bytes, err := w.doPost(getMOPath, req_data)
	if err != nil {
		return nil, err
	}
	var mo_rsp []*MOResult
	err = json.Unmarshal(resp_bytes, &mo_rsp)
	if err != nil {
		return nil, err
	}
	return mo_rsp, nil
}

func (w *SmsClient) GetReport() ([]*ReportResult, error) {
	tokenRsp, err := w.GetToken()
	if err != nil {
		return nil, err
	}
	tmp_sign := tokenRsp.Token + w.custPwd
	md5sign := md5.Sum([]byte(tmp_sign))
	tokenReq := &moReq{
		CustCode: w.custCode,
		TokenId:  tokenRsp.TokenId,
		Sign:     fmt.Sprintf("%x", md5sign),
	}
	req_data, err := json.Marshal(tokenReq)
	resp_bytes, err := w.doPost(getReport, req_data)
	if err != nil {
		return nil, err
	}
	var report_rsp []*ReportResult
	err = json.Unmarshal(resp_bytes, &report_rsp)
	if err != nil {
		return nil, err
	}
	return report_rsp, nil
}

func (w *SmsClient) QueryAccount() (*AccountResult, error) {
	tokenRsp, err := w.GetToken()
	if err != nil {
		return nil, err
	}
	tmp_sign := tokenRsp.Token + w.custPwd
	md5sign := md5.Sum([]byte(tmp_sign))
	tokenReq := &moReq{
		CustCode: w.custCode,
		TokenId:  tokenRsp.TokenId,
		Sign:     fmt.Sprintf("%x", md5sign),
	}
	req_data, err := json.Marshal(tokenReq)
	resp_bytes, err := w.doPost(queryAccountPath, req_data)
	if err != nil {
		return nil, err
	}
	var account_rsp *AccountResult
	err = json.Unmarshal(resp_bytes, &account_rsp)
	if err != nil {
		return nil, err
	}
	return account_rsp, nil
}

func (w *SmsClient) SendMsg(req *SmsReq) (*SmsRsp, error) {
	if req == nil {
		return nil, fmt.Errorf("Invalid req")
	}

	err := w.checkReq(req)
	if err != nil {
		return nil, err
	}

	msg_format, ok := sms_format_validate[req.MsgFmt]
	if !ok {
		return nil, fmt.Errorf("MsgFmt invalid.")
	}

	tmp_sign := req.Content + w.custPwd
	md5sign := md5.Sum([]byte(tmp_sign))

	need_report := "no"
	if req.NeedReport {
		need_report = "yes"
	}

	sms_send_req := &smsSendReq{
		CustCode:    w.custCode,
		Sign:        fmt.Sprintf("%x", md5sign),
		Content:     req.Content,
		DestMobiles: req.DestMobiles,
		Uid:         req.Uid,
		NeedReport:  need_report,
		MsgFmt:      msg_format,
		SpCode:      req.SpCode,
	}

	req_data, err := json.Marshal(sms_send_req)
	resp_bytes, err := w.doPost(sendMsgPath, req_data)
	if err != nil {
		return nil, err
	}
	sms_resp := w.defaultSmsRsp()
	err = json.Unmarshal(resp_bytes, sms_resp)
	if err != nil {
		return nil, err
	}

	return sms_resp, nil
}

func (w *SmsClient) SendVariantMsg(req *SmsVeriantInput) (*SmsRsp, error) {
	if req == nil {
		return nil, fmt.Errorf("Invalid req")
	}

	msg_format, ok := sms_format_validate[req.MsgFmt]

	if !ok {
		return nil, fmt.Errorf("MsgFmt invalid.")
	}

	tmp_sign := req.Content + w.custPwd
	md5sign := md5.Sum([]byte(tmp_sign))

	need_report := "no"
	if req.NeedReport {
		need_report = "yes"
	}

	sms_send_req := &SmsVariantReq{
		CustCode:   w.custCode,
		Sign:       fmt.Sprintf("%x", md5sign),
		Content:    req.Content,
		Params:     req.Params,
		Uid:        req.Uid,
		NeedReport: need_report,
		MsgFmt:     msg_format,
		SpCode:     req.SpCode,
	}

	req_data, err := json.Marshal(sms_send_req)
	resp_bytes, err := w.doPost(sendVariantPath, req_data)
	if err != nil {
		return nil, err
	}
	sms_resp := w.defaultSmsRsp()
	err = json.Unmarshal(resp_bytes, sms_resp)
	if err != nil {
		return nil, err
	}

	return sms_resp, nil
}

func (w *SmsClient) doPost(path string, req_data []byte) ([]byte, error) {
	http_req, err := http.NewRequest("POST", w.addr+path, strings.NewReader(string(req_data)))
	if err != nil {
		return nil, err
	}
	http_req.Header.Set("content-type", "application/json")
	resp, err := w.httpClient.Do(http_req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}