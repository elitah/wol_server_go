package main

import (
	"container/list"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/elitah/utils/exepath"
	"github.com/elitah/utils/logs"

	"github.com/astaxie/beego/httplib"
	"github.com/bitly/go-simplejson"
	"github.com/panjf2000/ants"
)

var (
	exeDir = exepath.GetExeDir()

	ErrClosed      = errors.New("client offline")
	ErrInvalidJson = errors.New("invalid json struct")
	ErrMacAddress  = errors.New("invalid mac address")
	ErrNoClient    = errors.New("no such client")
	ErrNoAdmin     = errors.New("no admin")
	ErrWarnLocked  = errors.New("warn locked")
	ErrEmptyRead   = errors.New("empty read")
	ErrEmptyWrite  = errors.New("empty write")
)

type OAuthConfig struct {
	Domain string `json:"domain"`
	Key    string `json:"key"`
	Secret string `json:"secret"`
}

type OAuthStore struct {
	Key    string
	Secret string
}

type DeviceStore struct {
	DeviceID string `json:"devid"`
	Admin    string `json:"admin"`
}

type UserStore struct {
	NodeID string      `json:"nodeid"`
	Warns  []WarnStore `json:"warns"`
}

type WolStore struct {
	NodeID   string   `json:"nodeid"`
	Servers  []string `json:"servers"`
	Machines []string `json:"machines"`
}

type WarnStore struct {
	DeviceID string `json:"devid"`
	Key      string `json:"key"`
	Location string `json:"location"`
	Title    string `json:"title"`
	Desp     string `json:"desp"`
}

func AESEncrypt(b cipher.Block, text string) (string, bool) {
	if nil != b && "" != text {
		plaintext := []byte(text)
		ciphertext := make([]byte, b.BlockSize()+len(plaintext))
		iv := ciphertext[:b.BlockSize()]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", false
		}
		stream := cipher.NewCFBEncrypter(b, iv)
		stream.XORKeyStream(ciphertext[b.BlockSize():], plaintext)
		return base64.URLEncoding.EncodeToString(ciphertext), true
	}
	return "", false
}

func AESDecrypt(b cipher.Block, text string) (string, bool) {
	if nil != b && "" != text {
		ciphertext, _ := base64.URLEncoding.DecodeString(text)
		if len(ciphertext) < b.BlockSize() {
			return "", false
		}
		iv := ciphertext[:b.BlockSize()]
		ciphertext = ciphertext[b.BlockSize():]
		stream := cipher.NewCFBDecrypter(b, iv)
		stream.XORKeyStream(ciphertext, ciphertext)
		return fmt.Sprintf("%s", ciphertext), true
	}
	return "", false
}

func HTMLBody(w http.ResponseWriter, body string) {
	fmt.Fprintf(w, `<html>
	<body>
		%s
	</body>
</html>`, body)
}

func JsAlert(w http.ResponseWriter, args ...string) {
	if 1 <= len(args) {
		//
		var location string = "/"
		//
		if 2 <= len(args) {
			location = args[1]
		}
		//
		fmt.Fprintf(w, `<html>
	<body>
		<script>
		alert("%s");
		window.location.href="%s";
		</script>
	</body>
</html>`, args[0], location)
	}
}

type CrossDevice struct {
	key string

	ssid string

	lan_ip string
}

type CrossServer struct {
	sync.RWMutex

	address string

	conn net.Conn

	flag uint32

	lastupdate time.Time
	lastusing  time.Time

	devices []*CrossDevice
}

func (this *CrossServer) Close() {
	//
	this.Lock()
	//
	if nil != this.conn {
		this.conn.Close()
	}
	//
	this.devices = nil
	//
	this.Unlock()
}

func (this *CrossServer) GetConn() net.Conn {
	this.RLock()
	conn := this.conn
	this.RUnlock()

	if nil == conn {
		logs.Warn("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		//
		if _conn, err := net.DialTimeout("tcp", this.address, 3*time.Second); nil == err {
			var buffer [1024]byte
			//
			this.Lock()
			//
			this.lastusing = time.Now()
			//
			_conn.Write([]byte(`{"cmd":"beat"}`))
			//
			_conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			//
			if n, err := _conn.Read(buffer[:]); nil == err {
				if 0 < n {
					var result = struct {
						Status bool `json:"status"`
					}{}
					//
					logs.Warn(string(buffer[:n]))
					//
					if err := json.Unmarshal(buffer[:n], &result); nil == err {
						if result.Status {
							conn = _conn
							this.conn = _conn

							//
							go func(conn net.Conn) {
								if nil != conn {
									var buffer [1024]byte
									for {
										time.Sleep(7 * time.Second)
										//
										this.Lock()
										//
										since := time.Since(this.lastusing)
										//
										logs.Info(since)
										//
										if 1*time.Minute > since {
											//
											conn.Write([]byte(`{"cmd":"beat"}`))
											//
											_conn.SetReadDeadline(time.Now().Add(3 * time.Second))
											//
											if n, err := _conn.Read(buffer[:]); nil == err {
												if 0 < n {
													var result = struct {
														Status bool `json:"status"`
													}{}
													//
													logs.Warn(string(buffer[:n]))
													if err := json.Unmarshal(buffer[:n], &result); nil == err {
														if result.Status {
															//
															this.Unlock()
															//
															continue
														} else {
															logs.Warn(err)
														}
													} else {
														logs.Warn(err)
													}
												} else {
													logs.Warn("short read")
												}
											} else {
												logs.Warn(err)
											}
										}
										// 取消连接
										this.conn = nil
										// 关闭连接
										conn.Close()
										// 解锁
										this.Unlock()
										//
										logs.Warn("connection closed")
										// 跳出
										break
									}
								}
							}(_conn)
						}
					}
				}
			}
			//
			this.Unlock()
		}
	} else {
		//
		this.Lock()
		//
		this.lastusing = time.Now()
		//
		this.Unlock()
	}

	return conn
}

func (this *CrossServer) Wakeup(key, mac string) bool {
	if "" != key && "" != mac {
		for _, item := range this.devices {
			if key == item.key {
				if conn := this.GetConn(); nil != conn {
					var buffer [1024]byte
					//
					this.Lock()
					//
					defer this.Unlock()
					//
					if data, err := json.Marshal(struct {
						Cmd string `json:"cmd"`
						Key string `json:"key"`
						Mac string `json:"mac"`
					}{
						Cmd: "wol",
						Key: key,
						Mac: mac,
					}); nil == err {
						//
						conn.Write(data)
						//
						conn.SetReadDeadline(time.Now().Add(3 * time.Second))
						//
						if n, err := conn.Read(buffer[:]); nil == err {
							if 0 < n {
								var result = struct {
									Status bool `json:"status"`
								}{}
								//
								logs.Warn(string(buffer[:n]))
								//
								if err := json.Unmarshal(buffer[:n], &result); nil == err {
									return result.Status
								} else {
									logs.Warn(err)
								}
							} else {
								logs.Warn("short read")
							}
						} else {
							logs.Warn(err)
						}
					} else {
						logs.Warn(err)
					}
				} else {
					logs.Warn("no conn")
				}
			}
		}
	}

	return false
}

func (this *CrossServer) Update(flags ...bool) bool {
	if 0 == len(flags) || !flags[0] {
		if 3*time.Minute > time.Since(this.lastupdate) {
			return true
		}
	}
	if atomic.CompareAndSwapUint32(&this.flag, 0x0, 0x1) {
		go func() {
			defer func() {
				atomic.StoreUint32(&this.flag, 0x0)
			}()

			if conn := this.GetConn(); nil != conn {
				var buffer [4096]byte
				//
				this.Lock()
				//
				defer this.Unlock()
				//
				conn.Write([]byte(`{"cmd":"client_list"}`))
				//
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				//
				if n, err := conn.Read(buffer[:]); nil == err {
					if 0 < n {
						type node struct {
							Key   string `json:"key"`
							SSID  string `json:"ssid"`
							LanIP string `json:"lan_ip"`
						}
						result := struct {
							Status   bool `json:"status"`
							Response struct {
								Count int64  `json:"count"`
								List  []node `json:"list"`
							} `json:"response"`
						}{}
						//
						logs.Warn(string(buffer[:n]))
						//
						if err := json.Unmarshal(buffer[:n], &result); nil == err {
							//
							if result.Status {
								//
								this.devices = nil
								//
								for _, item := range result.Response.List {
									this.devices = append(this.devices, &CrossDevice{
										key:    item.Key,
										ssid:   item.SSID,
										lan_ip: item.LanIP,
									})
								}
								//
								this.lastupdate = time.Now()
							}
						} else {
							logs.Error(err)
						}
					} else {
						logs.Error("empty read")
					}
				} else {
					logs.Error(err)
				}
			} else {
				logs.Error("no conn")
			}
		}()
		return true
	}
	return false
}

func (this *CrossServer) HTML(r *http.Request, machines []string, table bool) string {
	//
	var ss strings.Builder
	//
	if 0x0 != atomic.LoadUint32(&this.flag) {
		//
		ctx, _ := context.WithTimeout(r.Context(), 5*time.Second)
		//
		for 0x0 != atomic.LoadUint32(&this.flag) {
			select {
			case <-ctx.Done():
				return "<h3>超时!</h3>"
			case <-time.After(1 * time.Second):
				logs.Info("retry check...")
			}
		}
	}
	//
	if table {
		//
		v := url.Values{}
		//
		v.Set("address", this.address)
		//
		fmt.Fprintf(&ss, `<div style="padding: 1em; margin-bottom: 3em; border: 2px solid #ccc; background-color: #eee;">
			<h3 style="display: inline-block; position: relative; top: -1.7em; color: #f00; background-color: #eee;">客户端列表</h3>
			<p><a href="/wol_update?%s">强制刷新</a> | <a href="/">回到首页</a></p>
			<table>`, v.Encode())
		//
		for _, item := range this.devices {
			v.Set("key", item.key)

			fmt.Fprintf(&ss, `
				<tr>
					<td>%s<td>
					<td>%s<td>
					<td>%s<td>
					<td>
						<select onchange="device_wakeup(this);">
							<option value="_">---请选择---</option>`, item.key, item.ssid, item.lan_ip)

			for _, item := range machines {
				v.Set("mac", item)

				fmt.Fprintf(&ss, `
							<option value="%s">%s</option>`, v.Encode(), item)
			}

			fmt.Fprintf(&ss, `
						</select>
					</td>
				</tr>`)
		}
		//
		ss.WriteString(`
			</table>
		</div>
		<script>
		function device_wakeup(dom) {
			if ('_' != dom.value) {
				if (confirm('确认吗?')) {
					window.location.href = '/wol_wakeup?' + dom.value;
				}
				dom.value = '_';
			}
		}
		</script>`)
	} else {
		for _, item := range this.devices {
			fmt.Fprintf(&ss, "<p>Key: %s, SSID: %s, Lan ip: %s</p>", item.key, item.ssid, item.lan_ip)
		}
	}
	return ss.String()
}

type BoolWait struct {
	sync.WaitGroup

	result bool
}

func (this *BoolWait) Wait() {
	this.WaitGroup.Add(1)
	this.WaitGroup.Wait()
}

func (this *BoolWait) Done(result bool) {
	this.result = result
	this.WaitGroup.Done()
}

func (this *BoolWait) Result() bool {
	return this.result
}

type WolWait struct {
	Handler interface{}

	Key string

	Time time.Time
}

func (this *WolWait) Response(result bool) {
	if conn, ok := this.Handler.(net.Conn); ok {
		if _, err := io.WriteString(conn, fmt.Sprintf(`{"status":%v,"response":null}`, result)); nil != err {
			logs.Warn(err)
		}
	} else if b, ok := this.Handler.(*BoolWait); ok {
		b.Done(result)
	} else if ctx, ok := this.Handler.(context.Context); ok {
		select {
		case <-ctx.Done():
		default:
			if v := ctx.Value("result"); v != nil {
				if _result, ok := v.(*bool); ok {
					*_result = result
				}
			}
		}
	}
}

func (this *WolWait) IsTimeout() bool {
	if 3*time.Second < time.Since(this.Time) {
		this.Response(false)
		return true
	}
	return false
}

type WolClient struct {
	sync.RWMutex

	Conn net.Conn

	SSID  string
	LanIP string

	Admin string

	warnCnt uint64

	firstWarn time.Time
	prevWarn  time.Time
	lastWarn  time.Time

	nextWarn time.Time
}

func (this *WolClient) Update(conn net.Conn, ssid, ip string) {
	this.Lock()
	defer this.Unlock()

	if nil != conn {
		this.Conn = conn
	}

	this.SSID = ssid
	this.LanIP = ip
}

func (this *WolClient) Offline() {
	this.Lock()
	defer this.Unlock()

	this.Conn = nil
}

func (this *WolClient) WarnUpdate() {
	now := time.Now()

	this.Lock()
	defer this.Unlock()

	if this.firstWarn.IsZero() {
		this.firstWarn = now
	}

	if this.prevWarn.IsZero() {
		this.prevWarn = now
	}

	if this.lastWarn.IsZero() {
		this.lastWarn = now
	}

	if 10*time.Second < now.Sub(this.lastWarn) {
		this.firstWarn = now
		this.prevWarn = now
	} else {
		this.prevWarn = this.lastWarn
	}
	//
	this.lastWarn = now
}

func (this *WolClient) GetWarnDuration() (time.Duration, bool) {
	now := time.Now()

	this.Lock()
	defer this.Unlock()

	if this.firstWarn.IsZero() {
		return 0, false
	}

	if this.prevWarn.IsZero() {
		return 0, false
	}

	if this.lastWarn.IsZero() {
		return 0, false
	}

	if d := now.Sub(this.lastWarn); 10*time.Second < d {
		return this.lastWarn.Sub(this.firstWarn), false
	}

	return now.Sub(this.firstWarn), true
}

func (this *WolClient) Warn() string {
	nowtime := time.Now()

	this.Lock()
	defer this.Unlock()

	if "" != this.Admin {
		if this.nextWarn.IsZero() || nowtime.After(this.nextWarn) {
			this.nextWarn = nowtime.Add(1 * time.Minute)
			return this.Admin
		}
	}

	return ""
}

func (this *WolClient) GetWarnCount() uint64 {
	return atomic.AddUint64(&this.warnCnt, 1)
}

func (this *WolClient) HadAdmin(args ...string) bool {
	this.RLock()
	defer this.RUnlock()

	if 0 < len(args) && "" != args[0] {
		return args[0] == this.Admin
	}

	return "" != this.Admin
}

func (this *WolClient) SendWol(mac string) error {
	return this.SendCmd("wol_send", mac)
}

func (this *WolClient) SendShutDown(mac string) error {
	return this.SendCmd("shutdown_send", mac)
}

func (this *WolClient) SendReset() (err error) {
	if conn := this.getConn(); nil != conn {
		_, err = io.WriteString(conn, `{"cmd":"reset"}`)
	} else {
		err = ErrClosed
	}
	return
}

func (this *WolClient) SendCmd(cmd, mac string) error {
	if conn := this.getConn(); nil != conn {
		if d := this.convMac(mac); nil != d {
			if data, err := json.Marshal(struct {
				Cmd string   `json:"cmd"`
				Mac []uint32 `json:"mac"`
			}{
				Cmd: cmd,
				Mac: d,
			}); nil == err {
				logs.Info("<===", string(data))
				if n, err := conn.Write(data); nil == err {
					if 0 < n {
						return nil
					} else {
						return ErrEmptyWrite
					}
				} else {
					return err
				}
			} else {
				return err
			}
		} else {
			return ErrMacAddress
		}
	}
	return ErrClosed
}

func (this *WolClient) getConn() net.Conn {
	this.Lock()
	defer this.Unlock()

	return this.Conn
}

func (this *WolClient) convMac(mac string) []uint32 {
	if nums := strings.FieldsFunc(mac, func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}); 6 == len(nums) {
		var result [6]uint32
		for i, _ := range result {
			if v, err := strconv.ParseUint(nums[i], 16, 32); err == nil {
				result[i] = uint32(v) & 0xFF
			} else {
				return nil
			}
		}
		return result[:]
	}
	return nil
}

type WolServer struct {
	sync.RWMutex

	mPool   *ants.Pool
	mListen net.Listener

	mOAuthList map[string]*OAuthStore

	mList map[string]*WolClient

	mWait list.List
	mCE   chan struct{}

	mAES cipher.Block

	mCrossServerList map[string]*CrossServer
}

func NewWolServer(pool *ants.Pool, l net.Listener) *WolServer {
	var aes_block cipher.Block

	var buffer [16]byte

	if _, err := rand.Read(buffer[:]); nil == err {
		aes_block, _ = aes.NewCipher(buffer[:])
	}

	os.Mkdir(exeDir+"/db", 0755)

	return &WolServer{
		mPool:   pool,
		mListen: l,

		mOAuthList: make(map[string]*OAuthStore),

		mList: make(map[string]*WolClient),

		mCE: make(chan struct{}),

		mAES: aes_block,

		mCrossServerList: make(map[string]*CrossServer),
	}
}

func (this *WolServer) AddOAuth(domain, key, secret string) {
	if "" != domain && "" != key && "" != secret {
		this.mOAuthList[domain] = &OAuthStore{
			Key:    key,
			Secret: secret,
		}
	}
}

func (this *WolServer) ListenAndServe() error {
	if nil != this.mPool && nil != this.mListen {
		if list, err := filepath.Glob(exeDir + "/db/dev_*.json"); nil == err {
			//logs.Info(list)
			for _, path := range list {
				if 21 == len(filepath.Base(path)) {
					if data, err := ioutil.ReadFile(path); nil == err {
						j := DeviceStore{}
						if err := json.Unmarshal(data, &j); nil == err {
							if "" != j.DeviceID {
								logs.Warn("Load file ok: %s", path)
								// 存入map
								this.Lock()
								this.mList[j.DeviceID] = &WolClient{
									Admin: j.Admin,
								}
								this.Unlock()
							} else {
								logs.Warn("Invalid device id from file: %s", path)
							}
						} else {
							logs.Warn("json.Unmarshal: %s, %v", path, err)
						}
					} else {
						logs.Warn("ioutil.ReadFile: %s, %v", path, err)
					}
				} else {
					logs.Warn("Invalid filename: %s", path)
				}
			}
		}
		/*
			// 同步设备配置
			filepath.Walk(exeDir+"/db/*", func(path string, info os.FileInfo, err error) error {
				logs.Info(path, info.IsDir(), info.Size())
				if !info.IsDir() {
					name := info.Name()
					if 21 == len(name) {
						if strings.HasPrefix(name, "dev_") && strings.HasSuffix(name, ".json") {

						}
					}
					logs.Warn("Not sync: %s", path)
				} else if "db" != info.Name() {
					logs.Warn("Skip dir: %s", path)
					return filepath.SkipDir
				}
				return nil
			})
		*/
		// 接收设备请求
		for {
			if conn, err := this.mListen.Accept(); nil == err {
				if err := this.mPool.Submit(func() {
					logs.Info("%v <===> %v", conn.LocalAddr(), conn.RemoteAddr())
					this.HandlerConn(conn)
					logs.Info("%v <xxx> %v", conn.LocalAddr(), conn.RemoteAddr())
					conn.Close()
				}); nil != err {
					logs.Warn("ants.Submit:", err)
					conn.Close()
				}
			} else {
				return err
			}
		}
	}
	return errors.New("no pool or listener")
}

func (this *WolServer) WaitListTimeoutCheck() {
	ticker := time.NewTicker(1 * time.Second)
	defer func() {
		ticker.Stop()
	}()
	for {
		select {
		case <-this.mCE:
			return
		case <-ticker.C:
			if 0 < this.waitListLength() {
				this.Lock()

				for e := this.mWait.Front(); nil != e; e = this.waitListTimeout(e) {
				}

				this.Unlock()
			}
		}
	}
}

func (this *WolServer) Close() {
	close(this.mCE)

	if nil != this.mListen {
		this.mListen.Close()
	}
}

func (this *WolServer) HandlerConn(conn net.Conn) {
	var devid string

	var nothing_to_send bool

	buffer := make([]byte, 1024)

	response := struct {
		Status   bool        `json:"status"`
		Response interface{} `json:"response"`
	}{}

	for {
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))

		if n, err := conn.Read(buffer); nil == err {
			if 0 < n {
				if j, err := simplejson.NewJson(buffer[:n]); nil == err {
					logs.Info("===>", string(buffer[:n]))
					if cmd := j.GetPath("cmd").MustString(); "" != cmd {
						switch cmd {
						case "response":
							nothing_to_send = true

							if key := j.GetPath("response", "key").MustString(); "" != key {
								this.waitListResult(key, j.GetPath("response", "status").MustBool())
							} else {
								this.showConnInfo(devid, ErrInvalidJson)
							}
						case "bind":
							key := j.GetPath("key").MustString()
							ssid := j.GetPath("ssid").MustString()
							ip := j.GetPath("ip").MustString()
							// 检查参数
							if "" != key && "" != ssid && "" != ip {
								// 返回true
								response.Status = true
								// 同步对象
								if "" == devid {
									devid = key

									this.listAdd(devid, conn, ssid, ip)
								}
							} else {
								this.showConnInfo(devid, ErrInvalidJson)
							}
						case "client_list":
							// 返回true
							response.Status = true
							response.Response = this.listAll("")
						case "wol", "shutdown":
							key := j.GetPath("key").MustString()
							mac := j.GetPath("mac").MustString()
							if "" != key && "" != mac {
								if c := this.listGet(key); nil != c {
									if err := c.SendCmd(cmd+"_send", mac); nil != err {
										this.showConnInfo(key, err)
									} else {
										nothing_to_send = true

										this.waitListAdd(key, conn)

										this.showConnInfo(key, "send ok")
									}
								} else {
									this.showConnInfo(devid, ErrNoClient)
								}
							} else {
								this.showConnInfo(devid, ErrInvalidJson)
							}
						case "warn":
							if "" != devid {
								if c := this.listGet(devid); nil != c {
									//
									c.WarnUpdate()
									//
									if c.HadAdmin() {
										if admin := c.Warn(); "" != admin {
											if data, err := ioutil.ReadFile(exeDir + "/db/user_" + admin + ".json"); nil == err {
												j := UserStore{}
												if err := json.Unmarshal(data, &j); nil == err {
													for i, _ := range j.Warns {
														if j.Warns[i].DeviceID == devid {
															if "" != j.Warns[i].Key && "" != j.Warns[i].Title && "" != j.Warns[i].Desp {
																if err := this.mPool.Submit(func() {
																	//
																	var title, desp string
																	//
																	//{"errno":0,"errmsg":"success","dataset":"done"}
																	//{"errno":1024,"errmsg":"\u4e0d\u8981\u91cd\u590d\u53d1\u9001\u540c\u6837\u7684\u5185\u5bb9"}
																	_r := struct {
																		ErrNo   int    `json:"errno"`
																		ErrMsg  string `json:"errmsg"`
																		DataSet string `json:"dataset"`
																	}{}
																	//
																	if d, _ := c.GetWarnDuration(); true {
																		//
																		title = j.Warns[i].Title
																		//
																		desp = fmt.Sprintf(`设备ID：%s
位置：%s
时间：%s
报警次数：第%d次
已累计时长：%v
其他信息：
%s
`,
																			devid,
																			j.Warns[i].Location,
																			time.Now().Format("2006-01-02 15:04:05"),
																			c.GetWarnCount(),
																			func() string {
																				if 10*time.Second > d {
																					return "小于10秒"
																				}
																				return fmt.Sprintf("%.0f秒", d.Seconds())
																			}(),
																			j.Warns[i].Desp,
																		)
																	}
																	//
																	for i := 0; 5 > i; i++ {
																		if err := httplib.Post("https://sctapi.ftqq.com/"+j.Warns[i].Key+".send").
																			Param("text", title). // 通知标题
																			Param("desp", desp).  // 通知内容
																			ToJSON(&_r); nil == err {
																			//
																			if 0 == _r.ErrNo {
																				//
																				this.waitListResult(devid, true)
																				//
																				return
																			}
																			//
																			this.showConnInfo(devid, _r.ErrMsg)
																			//
																			time.Sleep(1 * time.Second)
																		} else {
																			this.showConnInfo(devid, err)
																		}
																	}
																	//
																	this.waitListResult(devid, false)
																}); nil == err {
																	nothing_to_send = true

																	this.waitListAdd(devid, conn)

																	this.showConnInfo(devid, "send warn ok")
																} else {
																	this.showConnInfo(devid, err)
																}
															} else {
																this.showConnInfo(devid, "invalid warn key, title, desc")
															}
															break
														}
													}
												} else {
													this.showConnInfo(devid, err)
												}
											} else {
												this.showConnInfo(devid, err)
											}
										} else {
											this.showConnInfo(devid, ErrWarnLocked)
										}
									} else {
										this.showConnInfo(devid, ErrNoAdmin)
									}
								} else {
									this.showConnInfo(devid, ErrNoClient)
								}
							} else {
								this.showConnInfo(devid, ErrNoClient)
							}
						case "reset":
							if key := j.GetPath("key").MustString(); "" != key {
								if c := this.listGet(key); nil != c {
									if err := c.SendReset(); nil != err {
										this.showConnInfo(key, err)
									} else {
										nothing_to_send = true

										this.showConnInfo(key, "send ok")
									}
								} else {
									this.showConnInfo(devid, ErrNoClient)
								}
							} else {
								this.showConnInfo(devid, ErrInvalidJson)
							}
						case "beat":
							response.Status = true
						}
					}
				} else {
					this.showConnInfo(devid, err)
				}
			} else {
				this.showConnInfo(devid, ErrEmptyRead)
			}
			if !nothing_to_send {
				// 回复
				if data, err := json.Marshal(&response); nil == err {
					logs.Info("<===", string(data))
					if n, err := conn.Write(data); nil == err {
						if 0 == n {
							this.showConnInfo(devid, ErrEmptyWrite)
						}
					} else {
						this.showConnInfo(devid, err)
					}
				} else {
					this.showConnInfo(devid, err)
				}
			}
			// 复位
			nothing_to_send = false
			response.Status = false
			response.Response = nil
		} else {
			this.showConnInfo(devid, err)

			break
		}
	}

	this.listDel(devid)
}

func (this *WolServer) GetUserInfo(r *http.Request) *url.Values {
	if nil != this.mAES {
		//logs.Info(r.Header.Get("cookie"))
		if c, err := r.Cookie("token"); nil == err && "" != c.Value {
			//logs.Info(c.Value)
			if userinfo, ok := AESDecrypt(this.mAES, c.Value); ok {
				if strings.HasPrefix(userinfo, "userinfo:") {
					userinfo = userinfo[9:]
					if u, err := url.ParseQuery(userinfo); nil == err {
						if username := u.Get("username"); "" != username {
							// 读取配置文件
							if nodeid := u.Get("nodeid"); "" != nodeid {
								return &u
							} else {
								logs.Warn("invalid nodeid")
							}
						} else {
							logs.Warn("invalid username")
						}
					} else {
						logs.Warn("not userinfo")
					}
				} else {
					logs.Warn("AESDecrypt failed")
				}
			} else {
				logs.Warn(err)
			}
		} else {
			logs.Warn(err)
		}
	}
	return nil
}

func (this *WolServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logs.Info(r.URL)

	defer func() {
		r.Header = nil
	}()

	switch r.URL.Path {
	case "/":
		if u := this.GetUserInfo(r); nil != u {
			logs.Info("username", u.Get("username"))
			logs.Info("userid", u.Get("userid"))
			logs.Info("nodeid", u.Get("nodeid"))
			logs.Info("avatar_url", u.Get("avatar_url"))
			if tmpl, err := template.ParseFiles(exeDir + "/index.tpl"); nil == err {
				// 用户配置
				ui := UserStore{}
				wol := WolStore{}
				// 读取配置文件
				if nodeid := u.Get("nodeid"); "" != nodeid {
					if data, err := ioutil.ReadFile(exeDir + "/db/user_" + nodeid + ".json"); nil == err {
						if err := json.Unmarshal(data, &ui); nil != err {
							logs.Warn(err)
						}
					} else {
						logs.Warn(err)
					}
					if data, err := ioutil.ReadFile(exeDir + "/db/wol_" + nodeid + ".json"); nil == err {
						if err := json.Unmarshal(data, &wol); nil == err {
							for _, item := range wol.Servers {
								if _, ok := this.mCrossServerList[item]; !ok {
									this.mCrossServerList[item] = &CrossServer{address: item}
								}
							}
						} else {
							logs.Warn(err)
						}
					} else {
						logs.Warn(err)
					}
				}
				if err = tmpl.Execute(w, struct {
					UserName   string
					UserID     string
					NodeID     string
					AvatarUrl  string
					DeviceList interface{}
					WarnList   []WarnStore
					ServerList []string
				}{
					UserName:   u.Get("username"),
					UserID:     u.Get("userid"),
					NodeID:     u.Get("nodeid"),
					AvatarUrl:  u.Get("avatar_url"),
					DeviceList: this.listAll(u.Get("nodeid")),
					WarnList:   ui.Warns,
					ServerList: wol.Servers,
				}); nil == err {
					return
				} else {
					logs.Warn(err)
				}
			} else {
				logs.Warn(err)
			}
			//
			HTMLBody(w, "<h3>页面无法加载</h3>")
			//
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	case "/favicon.ico":
		http.NotFound(w, r)
		return
	case "/device":
		if devid := r.FormValue("devid"); "" != devid {
			if u := this.GetUserInfo(r); nil != u {
				if c := this.listGet(devid); nil != c {
					if nodeid := u.Get("nodeid"); "" != nodeid {
						if c.HadAdmin(nodeid) {
							if d, warning := c.GetWarnDuration(); warning {
								HTMLBody(w, fmt.Sprintf(`<ul>
	<li>报警次数：%d</li>
	<br />
	<li>当前状态：<b style="color: red;">触发中</b></li>
	<br />
	<li>本次报警起始时间：%s</li>
	<li>本次报警前次时间：%s</li>
	<li>本次报警本次时间：%s</li>
	<li>本次报警累积时长：%v</li>
	<br />
	<li><a href="/">返回</a></li>
</ul>`,
									c.warnCnt,
									c.firstWarn.Format("2006-01-02 15:04:05"),
									c.prevWarn.Format("2006-01-02 15:04:05"),
									c.lastWarn.Format("2006-01-02 15:04:05"),
									d,
								))
							} else {
								HTMLBody(w, fmt.Sprintf(`<ul>
	<li>报警次数：%d</li>
	<br />
	<li>当前状态：<b style="color: green;">安全</b></li>
	<br />
	<li>上次报警起始时间：%s</li>
	<li>上次报警前次时间：%s</li>
	<li>上次报警本次时间：%s</li>
	<li>上次报警累积时长：%v</li>
	<br />
	<li><a href="/">返回</a></li>
</ul>`,
									c.warnCnt,
									c.firstWarn.Format("2006-01-02 15:04:05"),
									c.prevWarn.Format("2006-01-02 15:04:05"),
									c.lastWarn.Format("2006-01-02 15:04:05"),
									d,
								))
							}
							return
						}
						//
						HTMLBody(w, "<h3>无权访问此设备，请<a href=\"/\">返回首页</a></h3>")
						//
						return
					}
				}
			}
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
		} else {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusFound)
		}
		return
	case "/wol_add", "/wol_del":
		address := r.URL.Query().Get("address")
		mac := r.URL.Query().Get("mac")
		//
		if "" != address || "" != mac {
			if "" != address {
				for {
					if host, port, _ := net.SplitHostPort(address); "" != host && "" != port {
						if i, err := strconv.Atoi(port); nil == err {
							if 2 <= strings.Count(host, ".") && 0 < i && 65535 >= i {
								break
							}
						}
					}
					address = ""
					break
				}
			}
			if "" != mac {
				if 17 == len(mac) {
					for i := 0; 17 > i; i++ {
						logs.Info(mac[i])
						switch mac[i] {
						case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
						case 'a', 'b', 'c', 'd', 'e', 'f':
						case 'A', 'B', 'C', 'D', 'E', 'F':
						case '-', ':':
						default:
							mac = ""
							i = 9999
						}
					}
				}
			}
			if "" != address || "" != mac {
				if u := this.GetUserInfo(r); nil != u {
					if nodeid := u.Get("nodeid"); "" != nodeid {
						wol := WolStore{}
						if data, err := ioutil.ReadFile(exeDir + "/db/wol_" + nodeid + ".json"); nil == err {
							if err := json.Unmarshal(data, &wol); nil != err {
								logs.Warn(err)
							}
						} else {
							if f, err := os.OpenFile(exeDir+"/db/wol_"+nodeid+".json", os.O_RDWR|os.O_CREATE, 0644); nil == err {
								f.Truncate(0)
								f.Close()
							}
							logs.Warn(err)
						}
						if "/wol_add" == r.URL.Path {
							if "" != address {
								if 0 < len(wol.Servers) {
									for _, item := range wol.Servers {
										if address == item {
											address = ""
											break
										}
									}
								}
							}
							if "" != mac {
								if 0 < len(wol.Machines) {
									for _, item := range wol.Machines {
										if mac == item {
											mac = ""
											break
										}
									}
								}
							}
						} else {
							//
							var ok = false
							//
							if "" != address {
								if 0 < len(wol.Servers) {
									for i, item := range wol.Servers {
										if address == item {
											if 1 == len(wol.Servers) {
												wol.Servers = []string{}
											} else {
												_tmp := wol.Servers
												wol.Servers = nil
												wol.Servers = append(wol.Servers, _tmp[0:i]...)
												wol.Servers = append(wol.Servers, _tmp[i+1:]...)
											}
											//
											ok = true
											//
											break
										}
									}
								}
								if !ok {
									address = ""
								}
							}
							//
							if "" != mac {
								if 0 < len(wol.Machines) {
									for i, item := range wol.Machines {
										if address == item {
											if 1 == len(wol.Machines) {
												wol.Machines = []string{}
											} else {
												_tmp := wol.Machines
												wol.Machines = nil
												wol.Machines = append(wol.Machines, _tmp[0:i]...)
												wol.Machines = append(wol.Machines, _tmp[i+1:]...)
											}
											//
											ok = true
											//
											break
										}
									}
								}
								if !ok {
									mac = ""
								}
							}
						}
						if "" != address || "" != mac {
							//
							wol.NodeID = nodeid
							//
							if "/wol_add" == r.URL.Path {
								//
								if "" != address {
									wol.Servers = append(wol.Servers, address)
								}
								//
								if "" != mac {
									wol.Machines = append(wol.Machines, mac)
								}
							} else {
								if "" != address {
									if server, ok := this.mCrossServerList[address]; ok {
										delete(this.mCrossServerList, address)

										server.Close()
									}
								}
							}
							//
							if data, err := json.Marshal(&wol); nil == err {
								if err = ioutil.WriteFile(exeDir+"/db/wol_"+nodeid+".json", data, 0664); nil != err {
									logs.Warn(err)
								}
							} else {
								logs.Warn(err)
							}
						} else {
							logs.Warn("不存在")
						}
						//
						JsAlert(w, "成功!")
						//
						return
					}
				}
				w.Header().Set("Location", "/login")
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		//
		JsAlert(w, "您输入的地址无效!")
		//
		return
	case "/wol_server":
		if address := r.URL.Query().Get("address"); "" != address {
			if u := this.GetUserInfo(r); nil != u {
				// 读取配置文件
				if nodeid := u.Get("nodeid"); "" != nodeid {
					//
					wol := WolStore{}
					//
					if data, err := ioutil.ReadFile(exeDir + "/db/wol_" + nodeid + ".json"); nil == err {
						if err := json.Unmarshal(data, &wol); nil != err {
							logs.Warn(err)
						}
					} else {
						logs.Warn(err)
					}
					//
					if server, ok := this.mCrossServerList[address]; ok {
						//
						server.Update()
						//
						HTMLBody(w, server.HTML(r, wol.Machines, true))
					} else {
						//
						JsAlert(w, "没有找到!")
					}
					//
					return
				}
			}
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		//
		JsAlert(w, "没有找到!")
		//
		return
	case "/wol_update":
		if address := r.URL.Query().Get("address"); "" != address {
			if server, ok := this.mCrossServerList[address]; ok {
				if server.Update(true) {
					v := url.Values{}
					//
					v.Set("address", address)
					//
					JsAlert(w, "查询中!", fmt.Sprintf("/wol_server?%s", v.Encode()))
					//
					return
				}
			}
		}
		//
		JsAlert(w, "没有找到!")
		//
		return
	case "/wol_wakeup":
		if address := r.URL.Query().Get("address"); "" != address {
			if key := r.URL.Query().Get("key"); "" != key {
				if mac := r.URL.Query().Get("mac"); "" != mac {
					if u := this.GetUserInfo(r); nil != u {
						// 读取配置文件
						if nodeid := u.Get("nodeid"); "" != nodeid {
							//
							wol := WolStore{}
							//
							if data, err := ioutil.ReadFile(exeDir + "/db/wol_" + nodeid + ".json"); nil == err {
								if err := json.Unmarshal(data, &wol); nil != err {
									logs.Warn(err)
								}
							} else {
								logs.Warn(err)
							}
							//
							for _, item := range wol.Machines {
								if mac == item {
									if server, ok := this.mCrossServerList[address]; ok {
										if server.Wakeup(key, mac) {
											v := url.Values{}
											//
											v.Set("address", address)
											//
											JsAlert(w, "指令已发出", fmt.Sprintf("/wol_server?%s", v.Encode()))
											return
										}
									}
								}
							}
						}
					}
				}
			}
		}
		//
		JsAlert(w, "没有找到!")
		//
		return
	case "/control":
		q := r.URL.Query()
		if key := q.Get("key"); "" != key {
			if cmd := q.Get("cmd"); "" != cmd {
				switch cmd {
				case "wol", "shutdown":
					if mac := q.Get("mac"); "" != mac {
						if c := this.listGet(key); nil != c {
							if err := c.SendCmd(cmd+"_send", mac); nil != err {
								this.showConnInfo(key, err)
							} else {
								var wb BoolWait

								this.waitListAdd(key, &wb)

								this.showConnInfo(key, "http send ok")

								wb.Wait()

								fmt.Fprintf(w, `{"status":%v,"response":null}`, wb.Result())

								return
							}
						} else {
							this.showConnInfo(key, ErrNoClient)
						}
					}
				case "reset":
					if c := this.listGet(key); nil != c {
						if err := c.SendReset(); nil != err {
							this.showConnInfo(key, err)
						} else {
							this.showConnInfo(key, "http send ok")
							fmt.Fprint(w, `{"status":true,"response":null}`)
							return
						}
					} else {
						this.showConnInfo(key, ErrNoClient)
					}
				}
			}
		}
		fmt.Fprint(w, `{"status":false,"response":null}`)
		return
	case "/login":
		if nil != this.mAES {
			q := r.URL.Query()
			if code := q.Get("code"); "" == code {
				if result, ok := AESEncrypt(this.mAES, "oauth"); ok {
					if oauth, ok := this.mOAuthList[r.Host]; ok {
						// https://github.com/login/oauth/authorize
						v := url.Values{}
						v.Set("client_id", oauth.Key)
						v.Set("state", result)
						//v.Set("redirect_uri", fmt.Sprintf("https://%s/login", r.Host))
						u := url.URL{
							Scheme:   "https",
							Host:     "github.com",
							Path:     "/login/oauth/authorize",
							RawQuery: v.Encode(),
						}
						w.Header().Set("Location", u.String())
						w.WriteHeader(http.StatusFound)
						return
					} else {
						logs.Warn("invalid domain")
					}
				} else {
					logs.Warn("unable encrypt state")
				}
			} else if err := q.Get("error"); "" != err {
				logs.Warn(err)
			} else if state := q.Get("state"); "" != state {
				if _state, ok := AESDecrypt(this.mAES, state); ok && "oauth" == _state {
					if oauth, ok := this.mOAuthList[r.Host]; ok {
						response1 := struct {
							AccessToken string `json:"access_token"`
							Scope       string `json:"scope"`
							TokenType   string `json:"token_type"`
						}{}
						req := httplib.Get("https://github.com/login/oauth/access_token")
						req.Param("client_id", oauth.Key)
						req.Param("client_secret", oauth.Secret)
						req.Param("code", code)
						req.Header("Accept", "application/json")
						if err := req.ToJSON(&response1); nil == err {
							response2 := struct {
								UserName  string `json:"login"`
								UserID    int64  `json:"id"`
								NodeID    string `json:"node_id"`
								AvatarUrl string `json:"avatar_url"`
							}{}
							req := httplib.Get("https://api.github.com/user")
							req.Header("Accept", "application/json")
							req.Header("Authorization", "token "+response1.AccessToken)
							if err := req.ToJSON(&response2); nil == err {
								v := url.Values{}
								v.Set("username", response2.UserName)
								v.Set("userid", fmt.Sprint(response2.UserID))
								v.Set("nodeid", response2.NodeID)
								v.Set("avatar_url", response2.AvatarUrl)
								logs.Info(v.Encode())
								if result, ok := AESEncrypt(this.mAES, "userinfo:"+v.Encode()); ok {
									http.SetCookie(w, &http.Cookie{
										Name:     "token",
										Value:    result,
										Path:     "/",
										HttpOnly: true,
										MaxAge:   30 * 86400,
									})
									w.Header().Set("Location", "/")
									w.WriteHeader(http.StatusFound)
									return
								}
							} else {
								logs.Warn(err)
							}
						} else {
							logs.Warn(err)
						}
					} else {
						logs.Warn("invalid domain")
					}
				} else {
					logs.Warn("invalid login state")
				}
			} else {
				logs.Warn("invalid login request")
			}
		} else {
			logs.Warn("no aes module avaiable")
		}
		//
		HTMLBody(w, "<h3>无法登陆</h3>")
		//
		return
	case "/logout":
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
		//
		HTMLBody(w, "<h3>已退出</h3>")
		//
		return
	}

	http.NotFound(w, r)
}

func (this *WolServer) waitListAdd(key string, h interface{}) {
	if "" != key && nil != h {
		this.Lock()

		this.mWait.PushBack(&WolWait{
			Handler: h,
			Key:     key,
			Time:    time.Now(),
		})

		this.Unlock()
	}
}

// 已加锁
func (this *WolServer) waitListTimeout(e *list.Element) *list.Element {
	if nil != e {
		if w, ok := e.Value.(*WolWait); ok {
			if w.IsTimeout() {
				_e := e.Next()
				this.mWait.Remove(e)
				return _e
			} else {
				return e.Next()
			}
		}
	}

	return nil
}

func (this *WolServer) waitListFind(key string) *WolWait {
	this.Lock()
	defer this.Unlock()

	for e := this.mWait.Front(); nil != e; e = e.Next() {
		if w, ok := e.Value.(*WolWait); ok {
			if w.Key == key {
				this.mWait.Remove(e)
				return w
			}
		}
	}

	return nil
}

func (this *WolServer) waitListResult(key string, result bool) {
	if "" != key {
		if w := this.waitListFind(key); nil != w {
			w.Response(result)
		}
	}
}

func (this *WolServer) waitListLength() int {
	this.RLock()
	defer this.RUnlock()

	return this.mWait.Len()
}

func (this *WolServer) listGet(key string) *WolClient {
	this.RLock()
	defer this.RUnlock()

	if r, ok := this.mList[key]; ok {
		return r
	}

	return nil
}

func (this *WolServer) listAdd(key string, conn net.Conn, ssid, ip string) {
	if "" != key {
		c := this.listGet(key)

		if nil == c {
			c = &WolClient{
				Conn:  conn,
				SSID:  ssid,
				LanIP: ip,
			}

			this.Lock()

			if _c, ok := this.mList[key]; ok {
				c = _c
			} else {
				this.mList[key] = c
			}

			this.Unlock()

			j := DeviceStore{
				DeviceID: key,
				Admin:    c.Admin,
			}

			if b, err := json.Marshal(&j); nil == err {
				logs.Info("New device store to file")
				ioutil.WriteFile(exeDir+"/db/dev_"+key+".json", b, 0644)
			}
		}

		if nil != c {
			c.Update(conn, ssid, ip)
		}
	}
}

func (this *WolServer) listDel(key string) {
	if "" != key {
		if c := this.listGet(key); nil != c {
			c.Offline()
		}
	}
}

func (this *WolServer) listAll(admin string) interface{} {
	type _clientInfo struct {
		Key      string `json:"key"`
		Online   bool   `json:"online"`
		SSID     string `json:"ssid"`
		LanIP    string `json:"lan_ip"`
		GlobalIP string `json:"global_ip"`
	}

	result := struct {
		Count int           `json:"count"`
		List  []_clientInfo `json:"list"`
	}{
		Count: this.listLength(),
	}

	if 0 < result.Count {
		var i int

		this.RLock()
		defer this.RUnlock()

		for key, value := range this.mList {
			value.RLock()

			if "" != admin && admin != value.Admin {
				value.RUnlock()

				continue
			}

			cinfo := _clientInfo{
				Key: key,
				Online: nil != value.Conn,
			}

			if cinfo.Online {
				cinfo.SSID = value.SSID
				cinfo.LanIP = value.LanIP
				cinfo.GlobalIP = value.Conn.RemoteAddr().String()
			}

			result.List = append(result.List, cinfo)

			value.RUnlock()

			i++
		}
	}

	result.Count = len(result.List)

	return result
}

func (this *WolServer) listLength() int {
	this.RLock()
	defer this.RUnlock()

	return len(this.mList)
}

func (this *WolServer) showConnInfo(key string, arg interface{}) {
	if err, ok := arg.(error); ok {
		if "" != key {
			logs.Warn("\033[32;1m[%s]\033[0m: %v", key, err)
		} else {
			logs.Warn("\033[31;1m[Unkown]\033[0m: %v", err)
		}
	} else if msg, ok := arg.(string); ok {
		if "" != key {
			logs.Info("\033[32;1m[%s]\033[0m: %s", key, msg)
		} else {
			logs.Info("\033[31;1m[Unkown]\033[0m: %s", msg)
		}
	}
}

func panicError(args ...interface{}) {
	if 0 < len(args) {
		for i, _ := range args {
			if nil == args[i] {
				return
			}
		}

		logs.Error(args[0], args[1:]...)

		if "windows" == runtime.GOOS {
			time.Sleep(3 * time.Second)
		} else {
			time.Sleep(1 * time.Second)
		}

		logs.Close()

		os.Exit(0)

		select {}
	}
}

func initHttplib(rootCA, proxy string) {
	var u *url.URL

	var _t *tls.Config

	if "" == rootCA {
		rootCA = exeDir + "/rootCA.bin"
	}

	if info, err := os.Stat(rootCA); nil == err {
		if 0 < info.Size() {
			if data, err := ioutil.ReadFile(rootCA); nil == err {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(data) {
					_t = &tls.Config{
						RootCAs:            pool,
						InsecureSkipVerify: false,
					}
				}
			}
		}
	}

	if "" != proxy {
		if _u, err := url.Parse(proxy); nil == err {
			switch _u.Scheme {
			case "http", "https", "socks5":
				if "" != _u.Host {
					u = _u
				}
			}
		}
	}

	// 设置httplib默认参数
	httplib.SetDefaultSetting(httplib.BeegoHTTPSettings{
		ShowDebug:        false,
		UserAgent:        "httplib",
		ConnectTimeout:   5 * time.Second,
		ReadWriteTimeout: 15 * time.Second,
		TLSClientConfig:  _t,
		Proxy: func(req *http.Request) (*url.URL, error) {
			return u, nil
		},
		Transport: &http.Transport{
			MaxIdleConns:          64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: nil,
		EnableCookie:  false,
		Gzip:          false,
		DumpBody:      false,
		Retries:       3,
	})
}

func main() {
	var help bool

	var addrWol string
	var addrHttp string

	var oauthList string

	var ca string

	var proxy string

	flag.BoolVar(&help, "h", false, "This Help.")
	flag.StringVar(&addrWol, "l", ":4000", "wol listen address.")
	flag.StringVar(&addrHttp, "p", ":80", "http listen address.")
	flag.StringVar(&oauthList, "o", "", "github OAuth node list.")

	flag.StringVar(&ca, "ca", "", "CA filepath.")

	flag.StringVar(&proxy, "proxy", "", "proxy url.")

	flag.Parse()

	logs.SetLogger(logs.AdapterConsole, `{"level":99,"color":true}`)
	logs.EnableFuncCallDepth(true)
	logs.SetLogFuncCallDepth(3)
	logs.Async()

	defer logs.Close()

	logs.Info(exeDir)

	if help {
		// for help
	} else if "" != addrWol && "" != addrHttp {
		var wg sync.WaitGroup

		initHttplib(ca, proxy)

		p, err := ants.NewPool(1000)

		panicError("无法创建协程池", err)

		defer p.Release()

		// 创建wol监听
		l_wol, err := net.Listen("tcp", addrWol)

		panicError("无法监听TCP", err)

		// 创建http监听
		l_http, err := net.Listen("tcp", addrHttp)

		panicError("无法监听TCP", err)

		wol := NewWolServer(p, l_wol)

		if "" != oauthList {
			switch {
			default:
				if info, err := os.Stat(oauthList); nil == err {
					if 0 < info.Size() {
						var list []OAuthConfig
						//
						if data, err := ioutil.ReadFile(oauthList); nil == err {
							//
							if err := json.Unmarshal(data, &list); nil == err {
								for i, _ := range list {
									wol.AddOAuth(list[i].Domain, list[i].Key, list[i].Secret)
								}
							}
						}
					}
					break
				}
				if list := strings.Split(oauthList, ";"); 0 < len(list) {
					for _, item := range list {
						if arr := strings.Split(item, ":"); 3 <= len(arr) {
							wol.AddOAuth(arr[0], arr[1], arr[2])
						}
					}
				}
			}
		}

		// 监听wol
		p.Submit(func() {
			wg.Add(1)
			logs.Warn(wol.ListenAndServe())
			wg.Done()
		})

		// 监听wol
		p.Submit(func() {
			wg.Add(1)
			wol.WaitListTimeoutCheck()
			wg.Done()
		})

		// 监听http
		p.Submit(func() {
			wg.Add(1)
			h := http.Server{
				Handler: wol,
			}
			logs.Warn(h.Serve(l_http))
			wg.Done()
		})

		c_signal := make(chan os.Signal, 1)

		signal.Notify(c_signal, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

		ticker := time.NewTicker(5 * time.Second)

	BREAK:
		for {
			select {
			case <-c_signal:
				break BREAK
			case <-ticker.C:
			}
		}

		if nil != l_http {
			l_http.Close()
		}

		wol.Close()

		p.Submit(func() {
			time.Sleep(3 * time.Second)
			os.Exit(-1)
		})

		wg.Wait()

		return
	}

	flag.Usage()
}
