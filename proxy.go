package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	PROXY_PORT = "54731"
	MANAGEMENT_PORT = "36712"
	SECURITY_KEY = "32 character encryption key"
)

//for parsing json, variables must be started with uppercase
type Account struct {
	PassHash string
	IPs      []string
}

var Dials map[string]*net.Dialer

func clearlog() {
	ex, err := os.Executable()
	if err != nil {
		log.Println(err.Error())
		return
	}
	exPath := filepath.Dir(ex)
	for {
		os.WriteFile(path.Join(exPath, "log.txt"), []byte(""), 0644)
		time.Sleep(6 * time.Hour)
	}
}

func handleHTTPConnection(client net.Conn, host string, request []byte) {
	remote, err := Dials[strings.Split(client.LocalAddr().String(), ":")[0]].Dial("tcp", host+":80")
	//remote, err := net.Dial("tcp", host+":80")

	if err == nil {
		go remote.Write(request)
		go io.Copy(remote, client)
		go io.Copy(client, remote)
	} else {
		log.Println(err.Error())
	}
}

func handleHTTPSConnection(client net.Conn, host string, request []byte) {
	remote, err := Dials[strings.Split(client.LocalAddr().String(), ":")[0]].Dial("tcp", host+":443")
	//remote, err := net.Dial("tcp", host+":443")
	if err == nil {
		go client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		go io.Copy(remote, client)
		go io.Copy(client, remote)
	} else {
		log.Println(err.Error())
	}

}

func handleSOCKS5Connection(client net.Conn, host string, request []byte, port string) {
	remote, err := Dials[strings.Split(client.LocalAddr().String(), ":")[0]].Dial("tcp", host+":"+port)
	//remote, err := net.Dial("tcp", host+":"+port)
	if err == nil {
		request[1] = 0x00
		client.Write(request)
		go io.Copy(remote, client)
		go io.Copy(client, remote)
	} else {
		log.Println(err.Error())
		request[1] = 0x01
		client.Write(request)
		client.Close()
	}
}

func containsInt(s []int, str int) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func containsString(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func checkCredentials(username string, password string, ip string) bool {
	ex, err := os.Executable()
	if err != nil {
		log.Println(err.Error())
		return false
	}
	exPath := filepath.Dir(ex)
	//content, err := ioutil.ReadFile(path.Join(exPath, "accounts", username+".json"))

	f, err := os.Open(path.Join(exPath, "accounts", username+".json"))
	if err == nil {
		fileinfo, err := f.Stat()
		filesize := fileinfo.Size()
		buffer := make([]byte, filesize)

		f.Read(buffer)
		f.Close()

		if err == nil {
			var account Account
			json.Unmarshal(buffer, &account)

			hash := sha256.Sum256([]byte(password))
			if hex.EncodeToString(hash[:]) == account.PassHash && containsString(account.IPs, ip) {
				return true
			}
		} else {
			log.Println(err.Error())
		}
	} else {
		log.Println(err.Error())
	}
	return false
}

func createServer(ip string, port string) {
	l, err := net.Listen("tcp", ip+":"+port)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Listening on " + ip + ":" + port)
	log.Println("Listening on " + ip + ":" + port)
	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println(err)
		} else {
			go func(client net.Conn) {

				// make a temporary bytes var to read from the connection
				tmp := make([]byte, 4096)
				// read to the tmp var
				n, err := conn.Read(tmp)
				if err != nil {
					// log.Println if not normal error
					if err != io.EOF {
						fmt.Printf("Read error - %s\n", err)
					}
				}
				byteData := tmp[:n]
				if len(byteData) > 0 {
					if strings.Contains(string(byteData), "CONNECT ") {
						//HTTPS
						host := strings.Split(strings.ReplaceAll(string(byteData), ":443", ""), " ")[1]
						auth := ""
						headers := strings.Split(strings.ReplaceAll(string(byteData), "\r\n", "\n"), "\n")
						for i := 1; i < len(headers); i++ {
							if strings.Contains(headers[i], "Proxy-Authorization: Basic ") {
								auth = strings.Split(headers[i], "Basic ")[1]
							}
						}
						decoded, err := base64.StdEncoding.DecodeString(auth)
						if err == nil {
							split := strings.Split(string(decoded), ":")
							if len(split) >= 2 {
								if checkCredentials(split[0], split[1], strings.Split(client.LocalAddr().String(), ":")[0]) {
									log.Println(split[0] + " - " + host + " - " + strings.Split(client.LocalAddr().String(), ":")[0] + " - " + "HTTPS")
									handleHTTPSConnection(client, host, byteData)
								} else {
									er407 := "HTTP/1.1 407 Proxy Authentication Required\r\nDate: " + time.Now().UTC().String() + "\r\nProxy-Authenticate: Basic realm=\"Proxy by Joshua Pinti\"\r\n\r\n"
									go client.Write([]byte(er407))
								}
							}else {
								er407 := "HTTP/1.1 407 Proxy Authentication Required\r\nDate: " + time.Now().UTC().String() + "\r\nProxy-Authenticate: Basic realm=\"Proxy by Joshua Pinti\"\r\n\r\n"
								client.Write([]byte(er407))
							}
						}

					} else {
						if byteData[0] == 5 {
							//SOCKS5
							var authMethods []int
							for i := 2; i < int(byteData[1])+2; i++ {
								authMethods = append(authMethods, int(byteData[i]))
							}
							buff := make([]byte, 2)
							buff[0] = 0x05
							if containsInt(authMethods, 2) {
								buff[1] = 0x02
							} else {
								buff[1] = 0xff
							}
							client.Write(buff)
							if buff[1] == 0x02 {
								tmp := make([]byte, 4096)
								n, err := conn.Read(tmp)
								if err == nil {
									byteData := tmp[:n]
									if byteData[0] == 0x01 {
										usernameSlice := make([]byte, 0)
										passwordSlice := make([]byte, 0)
										i := 2
										for i < int(byteData[1])+2 {
											usernameSlice = append(usernameSlice, byteData[i])
											i++
										}
										t := i
										i++
										for i < t+1+int(byteData[t]) {
											passwordSlice = append(passwordSlice, byteData[i])
											i++
										}
										username := string(usernameSlice)
										password := string(passwordSlice)
										buff := make([]byte, 2)
										buff[0] = 0x01
										if checkCredentials(username, password, strings.Split(client.LocalAddr().String(), ":")[0]) {
											buff[1] = 0x00
											client.Write(buff)
											tmp := make([]byte, 4096)
											n, err := conn.Read(tmp)
											if err == nil {
												byteData := tmp[:n]
												if byteData[0] == 0x05 && byteData[1] == 0x01 {
													switch byteData[3] {
													case 0x01:
														ip := ""
														for i := 4; i < 8; i++ {
															ip += strconv.Itoa(int(byteData[i])) + "."
														}
														ip = ip[:len(ip)-1]
														port := make([]byte, 2)
														port[0] = byteData[len(byteData)-2]
														port[1] = byteData[len(byteData)-1]
														portString := strconv.Itoa(int(binary.BigEndian.Uint16(port)))
														log.Println(username + " - " + ip + " - " + strings.Split(client.LocalAddr().String(), ":")[0] + " - " + "SOCKS5")
														handleSOCKS5Connection(client, ip, byteData, portString)
														break
													case 0x03:
														ip := ""
														for i := 5; i < 5+int(byteData[4]); i++ {
															ip += string(byteData[i])
														}
														port := make([]byte, 2)
														port[0] = byteData[len(byteData)-2]
														port[1] = byteData[len(byteData)-1]
														portString := strconv.Itoa(int(binary.BigEndian.Uint16(port)))
														log.Println(username + " - " + ip + " - " + strings.Split(client.LocalAddr().String(), ":")[0] + " - " + "SOCKS5")
														handleSOCKS5Connection(client, ip, byteData, portString)
														break
													case 0x04:
														ip := ""
														for i := 4; i < 20; i++ {
															ip += strconv.Itoa(int(byteData[i])) + ":"
														}
														ip = ip[:len(ip)-1]
														port := make([]byte, 2)
														port[0] = byteData[len(byteData)-2]
														port[1] = byteData[len(byteData)-1]
														portString := strconv.Itoa(int(binary.BigEndian.Uint16(port)))
														log.Println(username + " - " + ip + " - " + strings.Split(client.LocalAddr().String(), ":")[0] + " - " + "SOCKS5")
														handleSOCKS5Connection(client, ip, byteData, portString)
														break
													default:
														client.Close()
														break
													}
												} else {
													client.Close()
												}
											}

										} else {
											buff[1] = 0x01
											client.Write(buff)
											client.Close()
										}
									} else {
										client.Close()
									}
								}
							}

						} else {
							//HTTP (most likely)
							headers := strings.Split(strings.ReplaceAll(string(byteData), "\r\n", "\n"), "\n")
							host, auth := "", ""
							for i := 1; i < len(headers); i++ {
								if strings.Contains(headers[i], "Host: ") {
									host = strings.Split(headers[i], ": ")[1]
								}
								if strings.Contains(headers[i], "Proxy-Authorization: Basic ") {
									auth = strings.Split(headers[i], "Basic ")[1]
								}
							}
							decoded, err := base64.StdEncoding.DecodeString(auth)
							if err == nil {
								split := strings.Split(string(decoded), ":")
								if len(split) >= 2 {
									if checkCredentials(split[0], split[1], strings.Split(client.LocalAddr().String(), ":")[0]) {
										log.Println(split[0] + " - " + host + " - " + strings.Split(client.LocalAddr().String(), ":")[0] + " - " + "HTTP")
										handleHTTPConnection(client, host, byteData)
									}else {
										er407 := "HTTP/1.1 407 Proxy Authentication Required\r\nDate: " + time.Now().UTC().String() + "\r\nProxy-Authenticate: Basic realm=\"Proxy by Joshua Pinti\"\r\n\r\n"
										client.Write([]byte(er407))
									}
								}else {
									er407 := "HTTP/1.1 407 Proxy Authentication Required\r\nDate: " + time.Now().UTC().String() + "\r\nProxy-Authenticate: Basic realm=\"Proxy by Joshua Pinti\"\r\n\r\n"
									client.Write([]byte(er407))
								}
							}
						}
					}
				} else {
					client.Close()
				}
			}(conn)
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	var privateIPBlocks []*net.IPNet
	for _, cidr := range []string{
		// don't check loopback ips
		//"127.0.0.0/8",    // IPv4 loopback
		//"::1/128",        // IPv6 loopback
		//"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

func checkIPAddress(ip string) bool {
    if net.ParseIP(ip) == nil {
        log.Printf("Invalid IP Address: %s\n", ip)
        return false
    }
	if ip == "127.0.0.1" || ip == "Invalid IP Address: <nil>" {
		return false
	}
    for i := 0; i < len(ip); i++ {
        switch ip[i] {
        case '.':
            return true
        case ':':
            return false
        }
    }
	return false
}

func decode(encrypted string) string {
	key := []byte(SECURITY_KEY)
	cipherText, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		panic("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	return fmt.Sprintf("%s", cipherText)
}

func RemoveIndex(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

func add(w http.ResponseWriter, req *http.Request) {
	ex, err := os.Executable()
	if err != nil {
		log.Println(err.Error())
		return
	}
	exPath := filepath.Dir(ex)
	data := req.URL.Query().Get("data")
	if err == nil {
		received := strings.Split(decode(data), ":")

		username := received[0]
		passhash := received[1]
		ip := strings.Split(fmt.Sprint(req.Context().Value(http.LocalAddrContextKey)), ":")[0]
		log.Println("ADD - " + username + " - " + ip)
		
		//no idea why this is happening, just accept that this fixes it
		weirdNumber := int([]byte(received[2])[len(received[2])-1])
		key := string([]byte(received[2])[:len(received[2])-weirdNumber])

		if key == SECURITY_KEY {
			if _, err := os.Stat(path.Join(exPath, "accounts", username+".json")); errors.Is(err, os.ErrNotExist) {
				os.Create(path.Join(exPath, "accounts", username + ".json"))
				var account Account
				account.IPs = make([]string, 0)
				account.PassHash = passhash
				account.IPs = append(account.IPs, ip)
				n, err := json.Marshal(account)
				if err == nil {
					os.WriteFile(path.Join(exPath, "accounts", username+".json"), []byte(n), 0644)
					w.WriteHeader(200)
				} else {
					log.Println(err.Error())
					w.WriteHeader(500)
				}
			} else {
				content, err := ioutil.ReadFile(path.Join(exPath, "accounts", username+".json"))
				if err == nil {
					var account Account
					err := json.Unmarshal(content, &account)
					account.PassHash = passhash
					account.IPs = append(account.IPs, ip)
					n, err := json.Marshal(account)
					if err == nil {
						os.WriteFile(path.Join(exPath, "accounts", username+".json"), []byte(n), 0644)
						w.WriteHeader(200)
					} else {
						log.Println(err.Error())
						w.WriteHeader(500)
					}
				} else {
					log.Println(err.Error())
					w.WriteHeader(500)
				}
			}
		} else {
			log.Println("Invalid Key Attempt")
			w.WriteHeader(401)
		}
	} else {
		log.Println(err.Error())
		w.WriteHeader(500)
	}
}

func remove(w http.ResponseWriter, req *http.Request) {
	ex, err := os.Executable()
	if err != nil {
		log.Println(err.Error())
		return
	}
	exPath := filepath.Dir(ex)
	data := req.URL.Query().Get("data")
	if err == nil {
		received := strings.Split(decode(data), ":")
		username := received[0]
		ip := strings.Split(fmt.Sprint(req.Context().Value(http.LocalAddrContextKey)), ":")[0]
		log.Println("REMOVE - " + username + " - " + ip)

		//no idea why this is happening, just accept that this fixes it
		weirdNumber := int([]byte(received[1])[len(received[1])-1])
		key := string([]byte(received[1])[:len(received[1])-weirdNumber])

		if key == SECURITY_KEY {
			content, err := ioutil.ReadFile(path.Join(exPath, "accounts", username+".json"))
			if err == nil {
				var account Account
				json.Unmarshal(content, &account)
				for i := 0; i < len(account.IPs); i++ {
					if ip == account.IPs[i] {
						account.IPs = RemoveIndex(account.IPs, i)
					}
				}
				n, err := json.Marshal(account)
				if err == nil {
					os.WriteFile(path.Join(exPath, "accounts", username+".json"), []byte(n), 0644)
					w.WriteHeader(200)
				} else {
					log.Println(err.Error())
					w.WriteHeader(500)
				}
			} else {
				log.Println(err.Error())
				w.WriteHeader(500)
			}
		} else {
			log.Println("Invalid Key Attempt")
			w.WriteHeader(401)
		}
	} else {
		log.Println(err.Error())
		w.WriteHeader(500)
	}
}

func modify(w http.ResponseWriter, req *http.Request) {
	ex, err := os.Executable()
	if err != nil {
		log.Println(err.Error())
		return
	}
	exPath := filepath.Dir(ex)
	data := req.URL.Query().Get("data")
	if err == nil {
		received := strings.Split(decode(data), ":")
		username := received[0]
		passhash := received[1]
		log.Println("MODIFY - " + username)

		//no idea why this is happening, just accept that this fixes it
		weirdNumber := int([]byte(received[2])[len(received[2])-1])
		key := string([]byte(received[2])[:len(received[2])-weirdNumber])

		if key == SECURITY_KEY {
			content, err := ioutil.ReadFile(path.Join(exPath, "accounts", username+".json"))
			if err == nil {
				var account Account
				json.Unmarshal(content, &account)
				account.PassHash = passhash
				n, err := json.Marshal(account)
				if err == nil {
					os.WriteFile(path.Join(exPath, "accounts", username+".json"), []byte(n), 0644)
					w.WriteHeader(200)
				} else {
					log.Println(err.Error())
					w.WriteHeader(500)
				}
			} else {
				log.Println(err.Error())
				w.WriteHeader(500)
			}
		} else {
			log.Println("Invalid Key Attempt")
			w.WriteHeader(401)
		}
	} else {
		log.Println(err.Error())
		w.WriteHeader(500)
	}
}

func main() {
	go clearlog()
	ifaces, err := net.Interfaces()
	total := 0
	Dials = map[string]*net.Dialer{}
	if err == nil {
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err == nil {
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if checkIPAddress(ip.To4().String()) {
						Dials[ip.String()] = &net.Dialer{
							LocalAddr: &net.TCPAddr{
								IP:   net.ParseIP(ip.String()),
								Port: 0,
							},
						}
						go createServer(ip.String(), PROXY_PORT)
						total++
					}
				}
			}
		}
	}
	log.Println("Total Active IPs: " + strconv.Itoa(total))
	fmt.Println("Total Active IPs: " + strconv.Itoa(total))
	http.HandleFunc("/add", add)
	http.HandleFunc("/remove", remove)
	http.HandleFunc("/modify", modify)
	http.ListenAndServe("0.0.0.0:" + MANAGEMENT_PORT, nil)
}

