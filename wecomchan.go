package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math"
    "mime/multipart"
	"net"
    "net/http"
    "os"
    "reflect"
    "strings"
    "time"

    "github.com/go-redis/redis/v8"
)

/*-------------------------------  环境变量配置 begin  -------------------------------*/

var Sendkey = GetEnvDefault("SENDKEY", "set_a_sendkey")
var WecomCid = GetEnvDefault("WECOM_CID", "企业微信公司ID")
var WecomAids = strings.Split(GetEnvDefault("WECOM_AIDS", "企业微信应用ID"), ",")
var WecomSecrets = strings.Split(GetEnvDefault("WECOM_SECRETS", "企业微信应用Secret"), ",")
var WecomToUid = GetEnvDefault("WECOM_TOUID", "@all")
var RedisStat = GetEnvDefault("REDIS_STAT", "OFF")
var RedisAddr = GetEnvDefault("REDIS_ADDR", "localhost:6379")
var RedisPassword = GetEnvDefault("REDIS_PASSWORD", "")
var ctx = context.Background()

/*-------------------------------  环境变量配置 end  -------------------------------*/

/*-------------------------------  企业微信服务端API begin  -------------------------------*/

var GetTokenApi = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s"
var SendMessageApi = "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%s"
var UploadMediaApi = "https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token=%s&type=%s"

/*-------------------------------  企业微信服务端API end  -------------------------------*/

const RedisTokenKeyPrefix = "access_token_"

type Msg struct {
    Content string `json:"content"`
}
type Pic struct {
    MediaId string `json:"media_id"`
}
type JsonData struct {
    ToUser                 string `json:"touser"`
    AgentId                string `json:"agentid"`
    MsgType                string `json:"msgtype"`
    DuplicateCheckInterval int    `json:"duplicate_check_interval"`
    Text                   Msg    `json:"text"`
    Image                  Pic    `json:"image"`
}

// GetEnvDefault 获取配置信息，未获取到则取默认值
func GetEnvDefault(key, defVal string) string {
    val, ex := os.LookupEnv(key)
    if !ex {
        return defVal
    }
    return val
}

// ParseJson 将json字符串解析为map
func ParseJson(jsonStr string) map[string]interface{} {
    var wecomResponse map[string]interface{}
    if string(jsonStr) != "" {
        err := json.Unmarshal([]byte(string(jsonStr)), &wecomResponse)
        if err != nil {
            log.Println("生成json字符串错误")
        }
    }
    return wecomResponse
}

// GetRemoteToken 从企业微信服务端API获取access_token，存在redis服务则缓存
func GetRemoteToken(corpId, appSecret, appID string) string {
    getTokenUrl := fmt.Sprintf(GetTokenApi, corpId, appSecret)
    log.Println("getTokenUrl==>", getTokenUrl)
    resp, err := http.Get(getTokenUrl)
    if err != nil {
        log.Println(err)
    }
    defer resp.Body.Close()
    respData, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Println(err)
    }
    tokenResponse := ParseJson(string(respData))
    log.Println("企业微信获取access_token接口返回==>", tokenResponse)
    accessToken := tokenResponse["access_token"].(string)

    if RedisStat == "ON" {
        log.Println("prepare to set redis key")
        rdb := RedisClient()
        // access_token有效时间为7200秒(2小时)
        set, err := rdb.SetNX(ctx, RedisTokenKeyPrefix+appID, accessToken, 7000*time.Second).Result()
        log.Println(set)
        if err != nil {
            log.Println(err)
        }
    }
    return accessToken
}

// RedisClient redis客户端
func RedisClient() *redis.Client {
    rdb := redis.NewClient(&redis.Options{
        Addr:     RedisAddr,
        Password: RedisPassword, // no password set
        DB:       0,             // use default DB
    })
    return rdb
}

// PostMsg 推送消息
func PostMsg(postData JsonData, postUrl string) (string, error) {
    // 序列化请求数据为 JSON
    postJson, err := json.Marshal(postData)
    if err != nil {
        return "", fmt.Errorf("failed to marshal JSON data: %w", err)
    }
    
    // 处理特殊字符替换
    jsonString := string(postJson)
    jsonString = strings.Replace(jsonString, `\\n`, `\n`, -1)
    log.Printf("postJson: %s", jsonString)
    log.Printf("postUrl: %s", postUrl)
    
    // 创建 HTTP 请求
    req, err := http.NewRequestWithContext(context.Background(), "POST", postUrl, bytes.NewBuffer([]byte(jsonString)))
    if err != nil {
        return "", fmt.Errorf("failed to create HTTP request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")
    
    // 使用共享的 HTTP 客户端实例
    resp, err := httpClient.Do(req)
    if err != nil {
        return "", fmt.Errorf("failed to send HTTP request: %w", err)
    }
    defer resp.Body.Close()
    
    // 检查 HTTP 状态码
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("unexpected HTTP status: %s", resp.Status)
    }
    
    // 读取响应内容
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body: %w", err)
    }
    
    // 解析响应数据并记录日志
    mediaResp := ParseJson(string(body))
    log.Printf("企业微信发送应用消息接口返回: %v", mediaResp)
    
    return string(body), nil
}

// UploadMedia  上传临时素材并返回mediaId
func UploadMedia(msgType string, req *http.Request, accessToken string) (string, float64) {
    // 企业微信图片上传不能大于2M
    _ = req.ParseMultipartForm(2 << 20)
    imgFile, imgHeader, err := req.FormFile("media")
    log.Printf("文件大小==>%d字节", imgHeader.Size)
    if err != nil {
        log.Fatalln("图片文件出错==>", err)
        // 自定义code无效的图片文件
        return "", 400
    }
    buf := new(bytes.Buffer)
    writer := multipart.NewWriter(buf)
    if createFormFile, err := writer.CreateFormFile("media", imgHeader.Filename); err == nil {
        readAll, _ := io.ReadAll(imgFile)
        createFormFile.Write(readAll)
    }
    writer.Close()

    uploadMediaUrl := fmt.Sprintf(UploadMediaApi, accessToken, msgType)
    log.Println("uploadMediaUrl==>", uploadMediaUrl)
    newRequest, _ := http.NewRequest("POST", uploadMediaUrl, buf)
    newRequest.Header.Set("Content-Type", writer.FormDataContentType())
    log.Println("Content-Type ", writer.FormDataContentType())
    resp, err := httpClient.Do(newRequest)
    respData, _ := io.ReadAll(resp.Body)
    mediaResp := ParseJson(string(respData))
    log.Println("企业微信上传临时素材接口返回==>", mediaResp)
    if err != nil {
        log.Fatalln("上传临时素材出错==>", err)
        return "", mediaResp["errcode"].(float64)
    } else {
        return mediaResp["media_id"].(string), float64(0)
    }
}

// ValidateToken 判断accessToken是否失效
// true-未失效, false-失效需重新获取
func ValidateToken(errcode interface{}, appID string) bool {
    codeTyp := reflect.TypeOf(errcode)
    log.Println("errcode的数据类型==>", codeTyp)
    if !codeTyp.Comparable() {
        log.Printf("type is not comparable: %v", codeTyp)
        return true
    }

    // 如果errcode为42001表明token已失效，则清空redis中的token缓存
    if math.Abs(errcode.(float64)-float64(42001)) < 1e-3 {
        if RedisStat == "ON" {
            log.Printf("token已失效，开始删除redis中的key==>%s", RedisTokenKeyPrefix+appID)
            rdb := RedisClient()
            rdb.Del(ctx, RedisTokenKeyPrefix+appID)
            log.Printf("删除redis中的key==>%s完毕", RedisTokenKeyPrefix+appID)
        }
        log.Println("现需重新获取token")
        return false
    }
    return true
}

// GetAccessToken 获取企业微信的access_token
func GetAccessToken(appID, appSecret string) string {
    accessToken := ""
    if RedisStat == "ON" {
        log.Println("尝试从redis获取token")
        rdb := RedisClient()
        value, err := rdb.Get(ctx, RedisTokenKeyPrefix+appID).Result()
        if err == redis.Nil {
            log.Println("access_token does not exist, need get it from remote API")
        } else if err != nil {
            log.Printf("Error getting access token from Redis: %v", err)
        } else {
            accessToken = value
        }
    }
    if accessToken == "" {
        log.Println("get access_token from remote API")
        accessToken = GetRemoteToken(WecomCid, appSecret, appID)
    } else {
        log.Println("get access_token from redis")
    }
    return accessToken
}

// InitJsonData 初始化Json公共部分数据
func InitJsonData(msgType, appID string) JsonData {
    return JsonData{
        ToUser:                 WecomToUid,
        AgentId:                appID,
        MsgType:                msgType,
        DuplicateCheckInterval: 600,
    }
}

// 获取客户端真实IP地址
func getClientIP(r *http.Request) string {
    // 尝试从 X-Forwarded-For 头获取客户端IP
    xffHeader := r.Header.Get("X-Forwarded-For")
    if xffHeader != "" {
        // X-Forwarded-For 格式: client, proxy1, proxy2, ...
        ips := strings.Split(xffHeader, ",")
        // 返回最左边的IP，即客户端IP
        return strings.TrimSpace(ips[0])
    }
    
    // 尝试从 X-Real-IP 头获取客户端IP
    realIP := r.Header.Get("X-Real-IP")
    if realIP != "" {
        return realIP
    }
    
    // 如果没有代理头，则使用远程地址
    // 格式: "IP:端口"，所以需要分割
    remoteAddr := r.RemoteAddr
    if ip, _, err := net.SplitHostPort(remoteAddr); err == nil {
        return ip
    }
    
    return remoteAddr
}

// 共享的 HTTP 客户端实例，避免重复创建
var httpClient = &http.Client{
    Timeout: 30 * time.Second, // 设置请求超时时间
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
    },
}

// 主函数入口
func main() {
    // 设置日志内容显示文件名和行号
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    wecomChan := func(res http.ResponseWriter, req *http.Request) {
        // 获取并打印客户端真实IP
        clientIP := getClientIP(req)
        log.Printf("Client IP: %s", clientIP)
        
        _ = req.ParseForm()
        sendkey := req.FormValue("sendkey")
        if sendkey != Sendkey {
            log.Panicln("sendkey 错误，请检查")
        }
        appID := req.FormValue("appID")
        var appSecret string
        if appID == "" {
            if len(WecomAids) > 0 {
                appID = WecomAids[0]
                appSecret = WecomSecrets[0]
            } else {
                log.Panicln("未配置企业微信应用ID和Secret，请检查环境变量")
            }
        } else {
            found := false
            for i, aid := range WecomAids {
                if aid == appID {
                    appSecret = WecomSecrets[i]
                    found = true
                    break
                }
            }
            if !found {
                log.Panicln("未找到对应的企业微信应用ID，请检查")
            }
        }

        // 获取token
        accessToken := GetAccessToken(appID, appSecret)
        // 默认token有效
        tokenValid := true

        msgContent := req.FormValue("msg")
        msgType := req.FormValue("msg_type")
        ToUser := req.FormValue("to_user")
        if ToUser == "" {
            ToUser = "@all"
        }
        log.Println("mes_type=", msgType)
        // 默认mediaId为空
        mediaId := ""
        if msgType != "image" {
            log.Println("消息类型不是图片")
        } else {
            // token有效则跳出循环继续执行，否则重试3次
            for i := 0; i <= 3; i++ {
                var errcode float64
                mediaId, errcode = UploadMedia(msgType, req, accessToken)
                log.Printf("企业微信上传临时素材接口返回的media_id==>[%s], errcode==>[%f]\n", mediaId, errcode)
                tokenValid = ValidateToken(errcode, appID)
                if tokenValid {
                    break
                }

                accessToken = GetAccessToken(appID, appSecret)
            }
        }

        // 准备发送应用消息所需参数
        postData := InitJsonData(msgType, appID)
        postData.ToUser = ToUser
        postData.Text = Msg{
            Content: msgContent,
        }
        postData.Image = Pic{
            MediaId: mediaId,
        }

        postStatus := ""
        var err error
        for i := 0; i <= 3; i++ {
            sendMessageUrl := fmt.Sprintf(SendMessageApi, accessToken)
            postStatus, err = PostMsg(postData, sendMessageUrl)
            if err != nil {
                log.Printf("Error sending message: %v", err)
                postStatus = fmt.Sprintf(`{"errcode":500,"errmsg":"%s"}`, err.Error())
                tokenValid = false
            } else {
                postResponse := ParseJson(postStatus)
                errcode := postResponse["errcode"]
                log.Println("发送应用消息接口返回errcode==>", errcode)
                tokenValid = ValidateToken(errcode, appID)
            }
            
            // token有效则跳出循环继续执行，否则重试3次
            if tokenValid {
                break
            }
            
            // 刷新token
            accessToken = GetAccessToken(appID, appSecret)
        }

        res.Header().Set("Content-type", "application/json")
        _, err = res.Write([]byte(postStatus))
        if err != nil {
            log.Printf("Error writing response: %v", err)
        }
    }
    http.HandleFunc("/wecomchan", wecomChan)
    log.Fatal(http.ListenAndServe(":8080", nil))
}