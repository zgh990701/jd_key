package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	
	var data_center = "665aa05958cc22"
	var app_id = "286695_wc7P6cEITPofXY9Gx50ASaUN1qQY7NkE"
	var user = "董娟娟"
	var timestamp = "1723100466"
	var key = "675648e005e44bee97c7e2e25d89ec10"
	//X-Api-Signature
	t := timestamp
	// t := strconv.FormatInt(time.Now().Unix(), 10)
	fmt.Println(t)
	u := "%2Fk3cloud%2FKingdee.BOS.WebApi.ServicesStub.DynamicFormService.Save.common.kdsvc"
	context := fmt.Sprintf("POST\n%s\n\nx-api-nonce:%s\nx-api-timestamp:%s\n", u, t, t)

	app := strings.Split(app_id,"_")[0]
	id := strings.Split(app_id,"_")[1]
	idB64, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		fmt.Printf("err :%v", err)
		return
	}
	sec := []byte("0054f397c6234378b09ca7d3e5debce7")
	var res = []byte{}
	for k, v := range idB64 {
		res = append(res, v^sec[k])
	}

	secret := base64.StdEncoding.EncodeToString(res)
	// fmt.Println(secret)
	apiSig := HmacSha256ToHex(secret, context)

	b64 := base64.StdEncoding.EncodeToString([]byte(apiSig))
	// b64 := HmacSha256ToBase64(context, secret)
	fmt.Println(b64)

	//X-Kd-Appdata
	appdata := []byte(data_center+","+user+",2052,0")
	appData := base64.StdEncoding.EncodeToString(appdata)
	fmt.Println(appData)

	//X-Kd-Signature
	id_data := app_id+","+user+",2052,0"
	// idData := base64.StdEncoding.EncodeToString(id_data)
	sig1 := HmacSha256ToHex(key, id_data)
	sig := base64.StdEncoding.EncodeToString([]byte(sig1))
	// sig := HmacSha256ToBase64(idData, "910e2c638c3947eaa6c23386ddc1dc45")

	fmt.Printf("X-Api-ClientID %v \n", app)
	fmt.Printf("X-Api-Auth-Version %v \n", "2.0")
	fmt.Printf("x-api-timestamp %v \n", t)
	fmt.Printf("x-api-nonce %v \n", t)
	fmt.Printf("X-api-signheaders %v \n", "x-api-timestamp,x-api-nonce")
	fmt.Printf("X-Api-Signature %v \n", b64)
	fmt.Printf("X-Kd-Appkey %v \n", app_id)
	fmt.Printf("X-Kd-Appdata %v \n", appData)
	fmt.Printf("X-Kd-Signature %v \n", sig)
}

func HmacSha256(key string, data string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(data))

	return mac.Sum(nil)
}

// HmacSha256ToHex 将加密后的二进制转16进制字符串
func HmacSha256ToHex(key string, data string) string {
	return hex.EncodeToString(HmacSha256(key, data))
}

// HmacSha256ToHex 将加密后的二进制转Base64字符串
func HmacSha256ToBase64(key string, data string) string {
	return base64.URLEncoding.EncodeToString(HmacSha256(key, data))
}
