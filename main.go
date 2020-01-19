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

type DeviceStore struct {
	DeviceID string `json:"devid"`
	Admin    string `json:"admin"`
}

type UserStore struct {
	NodeID string      `json:"nodeid"`
	Warns  []WarnStore `json:"warns"`
}

type WarnStore struct {
	DeviceID string `json:"devid"`
	Key      string `json:"key"`
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

func (this *WolClient) Warn() string {
	nowtime := time.Now()

	this.Lock()
	defer this.Unlock()

	if "" != this.Admin {
		if this.nextWarn.IsZero() || nowtime.After(this.nextWarn) {
			this.nextWarn = nowtime.Add(3 * time.Minute)
			return this.Admin
		}
	}

	return ""
}

func (this *WolClient) HadAdmin() bool {
	this.RLock()
	defer this.RUnlock()

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

	mOAuthKey    string
	mOAuthSecret string

	mList map[string]*WolClient

	mWait list.List
	mCE   chan struct{}

	mAES cipher.Block
}

func NewWolServer(pool *ants.Pool, l net.Listener, uid, secret string) *WolServer {
	var aes_block cipher.Block

	if "" != uid && "" != secret {
		b := make([]byte, 16)
		if _, err := rand.Read(b); nil == err {
			aes_block, _ = aes.NewCipher(b)
		}
	}

	os.Mkdir(exeDir+"/db", 0755)

	return &WolServer{
		mPool:   pool,
		mListen: l,

		mOAuthKey:    uid,
		mOAuthSecret: secret,

		mList: make(map[string]*WolClient),

		mCE: make(chan struct{}),

		mAES: aes_block,
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

	var warn_cnt int64

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
							response.Response = this.listAll()
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
									if c.HadAdmin() {
										if admin := c.Warn(); "" != admin {
											if data, err := ioutil.ReadFile(exeDir + "/db/user_" + admin + ".json"); nil == err {
												j := UserStore{}
												if err := json.Unmarshal(data, &j); nil == err {
													for i, _ := range j.Warns {
														if j.Warns[i].DeviceID == devid {
															if "" != j.Warns[i].Key && "" != j.Warns[i].Title && "" != j.Warns[i].Desp {
																if err := this.mPool.Submit(func() {
																	warn_cnt++
																	if result, err := httplib.Get("https://sc.ftqq.com/"+j.Warns[i].Key+".send").
																		Param("text", fmt.Sprintf("%s (No.%d)", j.Warns[i].Title, warn_cnt)). // 通知标题
																		Param("desp", j.Warns[i].Desp).                                       // 通知内容
																		String(); nil == err {
																		//{"errno":0,"errmsg":"success","dataset":"done"}
																		//{"errno":1024,"errmsg":"\u4e0d\u8981\u91cd\u590d\u53d1\u9001\u540c\u6837\u7684\u5185\u5bb9"}
																		_r := struct {
																			ErrNo   int    `json:"errno"`
																			ErrMsg  string `json:"errmsg"`
																			DataSet string `json:"dataset"`
																		}{}
																		if err := json.Unmarshal([]byte(result), &_r); nil == err {
																			if 0 == _r.ErrNo {
																				this.waitListResult(devid, true)
																				return
																			}
																			this.showConnInfo(devid, _r.ErrMsg)
																		} else {
																			this.showConnInfo(devid, err)
																		}
																	} else {
																		this.showConnInfo(devid, err)
																	}
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

func (this *WolServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logs.Info(r.URL)

	defer func() {
		r.Header = nil
	}()

	switch r.URL.Path {
	case "/":
		if nil != this.mAES {
			//logs.Info(r.Header.Get("cookie"))
			if c, err := r.Cookie("token"); nil == err && "" != c.Value {
				//logs.Info(c.Value)
				if userinfo, ok := AESDecrypt(this.mAES, c.Value); ok {
					if strings.HasPrefix(userinfo, "userinfo:") {
						userinfo = userinfo[9:]
						if u, err := url.ParseQuery(userinfo); nil == err {
							if username := u.Get("username"); "" != username {
								logs.Info("username", username)
								logs.Info("userid", u.Get("userid"))
								logs.Info("nodeid", u.Get("nodeid"))
								logs.Info("avatar_url", u.Get("avatar_url"))
								if tmpl, err := template.ParseFiles(exeDir + "/index.tpl"); nil == err {
									// 用户配置
									j := UserStore{}
									// 读取配置文件
									if nodeid := u.Get("nodeid"); "" != nodeid {
										if data, err := ioutil.ReadFile(exeDir + "/db/user_" + nodeid + ".json"); nil == err {
											if err := json.Unmarshal(data, &j); nil != err {
												logs.Warn(err)
											}
										} else {
											logs.Warn(err)
										}
									}
									if err = tmpl.Execute(w, struct {
										UserName  string
										UserID    string
										NodeID    string
										AvatarUrl string
										WarnList  []WarnStore
									}{
										UserName:  u.Get("username"),
										UserID:    u.Get("userid"),
										NodeID:    u.Get("nodeid"),
										AvatarUrl: u.Get("avatar_url"),
										WarnList:  j.Warns,
									}); nil == err {
										return
									} else {
										logs.Warn(err)
									}
								} else {
									logs.Warn(err)
								}
								fmt.Fprint(w, `<html>
	<body>
		<h3>页面无法加载</h3>
	</body>
</html>`)
								return
							} else {
								logs.Warn("invalid username")
							}
						} else {
							logs.Warn(err)
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
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	case "/favicon.ico":
		http.NotFound(w, r)
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
					// https://github.com/login/oauth/authorize
					v := url.Values{}
					v.Set("client_id", this.mOAuthKey)
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
				}
			} else if err := q.Get("error"); "" != err {
				logs.Warn(err)
			} else if state := q.Get("state"); "" != state {
				if _state, ok := AESDecrypt(this.mAES, state); ok && "oauth" == _state {
					response1 := struct {
						AccessToken string `json:"access_token"`
						Scope       string `json:"scope"`
						TokenType   string `json:"token_type"`
					}{}
					req := httplib.Get("https://github.com/login/oauth/access_token")
					req.Param("client_id", this.mOAuthKey)
					req.Param("client_secret", this.mOAuthSecret)
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
					logs.Warn("invalid login state")
				}
			} else {
				logs.Warn("invalid login request")
			}
		} else {
			logs.Warn("no aes module avaiable")
		}
		fmt.Fprint(w, `<html>
	<body>
		<h3>无法登陆</h3>
	</body>
</html>`)
		return
	case "/logout":
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
		fmt.Fprint(w, `<html>
<body>
<h3>已退出</h3>
</body>
</html>`)
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

func (this *WolServer) listAll() interface{} {
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

		result.List = make([]_clientInfo, result.Count)

		this.RLock()
		defer this.RUnlock()

		for key, value := range this.mList {
			value.RLock()

			result.List[i].Key = key

			result.List[i].Online = nil != value.Conn

			if result.List[i].Online {
				result.List[i].SSID = value.SSID
				result.List[i].LanIP = value.LanIP
				result.List[i].GlobalIP = value.Conn.RemoteAddr().String()
			}

			value.RUnlock()

			i++
		}
	}

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

func init() {
	var _t *tls.Config

	rootCA := exeDir + "/rootCA.bin"

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

	// 设置httplib默认参数
	httplib.SetDefaultSetting(httplib.BeegoHTTPSettings{
		ShowDebug:        false,
		UserAgent:        "httplib",
		ConnectTimeout:   5 * time.Second,
		ReadWriteTimeout: 15 * time.Second,
		TLSClientConfig:  _t,
		Proxy:            nil,
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

	var oauthKey string
	var oauthSecret string

	flag.BoolVar(&help, "h", false, "This Help.")
	flag.StringVar(&addrWol, "l", ":4000", "wol listen address.")
	flag.StringVar(&addrHttp, "p", ":80", "http listen address.")
	flag.StringVar(&oauthKey, "oauth_key", "", "github OAuth client id.")
	flag.StringVar(&oauthSecret, "oauth_secret", "", "github OAuth client secret.")

	flag.Parse()

	logs.Info(exeDir)

	if help {
		// for help
	} else if "" != addrWol && "" != addrHttp {
		var wg sync.WaitGroup

		logs.SetLogger(logs.AdapterConsole, `{"level":99,"color":true}`)
		logs.EnableFuncCallDepth(true)
		logs.SetLogFuncCallDepth(3)
		logs.Async()

		defer logs.Close()

		p, err := ants.NewPool(1000)

		panicError("无法创建协程池", err)

		defer p.Release()

		// 创建wol监听
		l_wol, err := net.Listen("tcp", addrWol)

		panicError("无法监听TCP", err)

		// 创建http监听
		l_http, err := net.Listen("tcp", addrHttp)

		panicError("无法监听TCP", err)

		wol := NewWolServer(p, l_wol, oauthKey, oauthSecret)

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
