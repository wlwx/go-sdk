## 未来无线 GO SDK

* 下载安装SDK
  `go get github.com/wlwx/go-sdk`

* 代码示例

```go
package main

import (
	"fmt"
	"github.com/wlwx/go-sdk/sms"
)

func main() {
	custom_name := "用户名称"
	custom_pwd := "用户密码"

	sms_client := sms.NewSmsClient("请求路径", custom_name, custom_pwd)

	// 发送普通短信（业务标识uid选填）
	req := &sms.SmsReq{
		Content:     "Go SDK 测试",
		DestMobiles: "232210369999",
		Uid:         "1",
		NeedReport:  true,
		SpCode:      "10690353",
		MsgFmt:      sms.SmsMsgUCS2,
	}
	resp, err := sms_client.SendMsg(req)

	// 发送变量短信
	req := &sms.SmsVeriantInput{
		Content: "${mobile}用户您好，今天{$var1}的天气，晴，温度${var2}度，事宜外出。",
		Uid:     "1",
		Params: []*sms.MobileVars{
			&sms.MobileVars{
				Mobile: "232210369999",
				Vars:   []string{"232210369999", "阴天", "11"},
			},
			&sms.MobileVars{
				Mobile: "232210369999",
				Vars:   []string{"232210369999", "阴天", "11"},
			},
		},
		NeedReport: true,
		SpCode:     "sp code",
		MsgFmt:     sms.SmsMsgUCS2,
	}
	resp, err := sms_client.SendVariantMsg(req)

	// 获取Token
	resp, err := sms_client.GetToken()

	// 获取用户上行
	resp, err := sms_client.GetMO()

	// 获取状态报告
	resp, err := sms_client.GetReport()

	// 获取账户余额
	resp, err := sms_client.QueryAccount()

	if err != nil {
		fmt.Printf("Error:%s\n", err.Error())
	} else {
		fmt.Printf("Resp:%v\n", resp)
	}
}
```