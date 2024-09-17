package receiver

// Borrowed and pacthed from miekg dns to support legacy md5

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// HMAC hashing codes. These are transmitted as domain names.
const (
	HmacSHA1   = "hmac-sha1."
	HmacSHA224 = "hmac-sha224."
	HmacSHA256 = "hmac-sha256."
	HmacSHA384 = "hmac-sha384."
	HmacSHA512 = "hmac-sha512."

	HmacMD5 = "hmac-md5.sig-alg.reg.int." // Deprecated: HmacMD5 is no longer supported. But!

	// default TSIG algo
	DefaultTsigAlgo string = "HMAC-MD5.SIG-ALG.REG.INT"
)

// HMAC Provider configuration, from md5
type TsigHMACProvider string

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func (key TsigHMACProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {

	// If we barf here, the caller is to blame
	rawsecret, err := fromBase64([]byte(key))
	if err != nil {
		return nil, err
	}
	var h hash.Hash
	switch dns.CanonicalName(t.Algorithm) {
	case HmacMD5:
		h = hmac.New(md5.New, rawsecret)
	case HmacSHA1:
		h = hmac.New(sha1.New, rawsecret)
	case HmacSHA224:
		h = hmac.New(sha256.New224, rawsecret)
	case HmacSHA256:
		h = hmac.New(sha256.New, rawsecret)
	case HmacSHA384:
		h = hmac.New(sha512.New384, rawsecret)
	case HmacSHA512:
		h = hmac.New(sha512.New, rawsecret)
	default:
		return nil, dns.ErrKeyAlg
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

func (key TsigHMACProvider) Verify(msg []byte, t *dns.TSIG) error {
	b, err := key.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(b, mac) {
		return dns.ErrSig
	}
	return nil
}

const (
	// we could transfer in AXFR or IXFR
	// but for the last we need additional
	// options such as Serial, NS, Mbox???
	TransferModeAXFR = 1001
	TransferModeIXFR = 1002
	TransferModeHTTP = 1003
	TransferModeNONE = 1004

	// some error conditions
	TransferModeUnknown = 0
)

func TransferModeAsString(mode int) string {
	names := map[int]string{
		TransferModeAXFR: "AXFR",
		TransferModeIXFR: "IXFR",
		TransferModeHTTP: "HTTP",
		TransferModeNONE: "NONE",
	}

	if _, ok := names[mode]; ok {
		return names[mode]
	}

	return names[TransferModeUnknown]
}

type TransferOptions struct {
	// a mode of data transfer
	Mode int `json:"mode"`

	// some options for IXFR
	Serial uint32 `json:"serial"`
	Ns     string `json:"ns"`
	Mbox   string `json:"mbox"`

	// optional TSIG key
	Key string `json:"key"`
}

// Getting SOA record of zone as transfer option
func RequestSOA(server string, zone string) (*TransferOptions, error) {

	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(Dot(zone), dns.TypeSOA)
	r, _, err := c.Exchange(m, server)
	if err != nil {
		// network error possible occurs
		return nil, err
	}

	if r == nil {
		// something went wrong
		err = fmt.Errorf("error occured on exchange")
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		// possible REFUSED response
		err = fmt.Errorf("error on receive code response")
		return nil, err
	}

	if len(r.Answer) == 0 {
		// May happen if the server is a recursor, not authoritative, since we query with RD=0
		err = fmt.Errorf("error on answer section")
		return nil, err
	}

	soa := r.Answer[0]
	switch rr := soa.(type) {
	case *dns.SOA:
		if r.Authoritative {
			var options TransferOptions
			options.Serial = rr.Serial
			options.Ns = rr.Ns
			options.Mbox = rr.Mbox

			return &options, nil
		}
	}

	err = fmt.Errorf("error on authority section")
	return nil, err

}

// Transferring zone from server via axfr with possible TSIG key
// to match specific view (see rotation methods)
func TransferZone(server string, zone string, options *TransferOptions) ([]dns.RR, error) {

	var out []dns.RR

	algo := ""
	var tsig map[string]string

	if options != nil && len(options.Key) > 0 {
		var err error
		if algo, tsig, err = GetTSIGOptions(options.Key); err != nil {
			return out, err
		}
	}

	dt := new(dns.Transfer)

	dt.DialTimeout = 10 * time.Second
	dt.ReadTimeout = 20 * time.Second

	m := new(dns.Msg)
	if tsig != nil {
		dt.TsigSecret = tsig
		for _, key := range dt.TsigSecret {
			provider := TsigHMACProvider(RemoveDot(key))
			dt.TsigProvider = &provider
			break
		}
	}

	if options == nil || options.Mode == TransferModeAXFR {
		m.SetAxfr(Dot(zone))
	}

	if options != nil && options.Mode == TransferModeIXFR {
		m.SetIxfr(Dot(zone), options.Serial, options.Ns, options.Mbox)
	}

	if tsig != nil {
		sig := dns.HmacMD5
		switch Dot(algo) {
		case HmacSHA256:
			sig = dns.HmacSHA256
		case HmacSHA512:
			sig = dns.HmacSHA512
		case DefaultTsigAlgo:
			sig = dns.HmacMD5
		}
		m.SetTsig(GetTSIGUser(tsig), sig, 300, time.Now().Unix())
	}

	c, err := dt.In(m, server)
	if err != nil {
		return out, err
	}

	for msg := range c {
		if msg.Error != nil {
			err = fmt.Errorf("error transferring zone '%s' from '%s', err:'%s'",
				zone, server, msg.Error)
			return out, err
		}
		out = append(out, msg.RR...)
	}

	return out, nil
}

func GetTSIGUser(tsig map[string]string) string {
	user := ""
	for u := range tsig {
		user = u
		break
	}
	return user
}

// convering TSIG in algo:user:secret notation into
// algorithm, and dns map to use in transfer function
func GetTSIGOptions(key string) (string, map[string]string, error) {

	algo := dns.HmacMD5
	tags := strings.Split(key, ":")
	if len(tags) != 2 && len(tags) != 3 {
		err := fmt.Errorf("incorrect TSIG string detected")
		return algo, nil, err
	}

	// we do not have algo specified, use it by default
	offset := 0
	if len(tags) == 3 {
		offset = 1
		algo = tags[0]
	}

	value := make(map[string]string)
	value[tags[offset]] = tags[offset+1]
	return algo, value, nil
}

func Dot(s string) string {
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "\"") {
		return fmt.Sprintf("%s.", s)
	}
	return s
}

func RemoveDot(s string) string {
	if strings.HasSuffix(s, ".") {
		if len(s) > 0 {
			return s[0 : len(s)-1]
		}
	}
	return s
}

func SlicesDelete(s []dns.RR, i, j int) []dns.RR {
	ret := make([]dns.RR, 0)
	ret = append(ret, s[:i]...)
	return append(ret, s[j:]...)
}

// md5 checksum as string
func Md5(s string) string {
	h := md5.New()
	_, err := io.WriteString(h, s)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func StringInSlice(key string, list []string) bool {
	for _, entry := range list {
		if entry == key {
			return true
		}
	}
	return false
}

func IntInSlice(key int, list []int) bool {
	for _, entry := range list {
		if entry == key {
			return true
		}
	}
	return false
}

func SliceInSlice(s1 []string, s2 []string) bool {
	for _, e := range s1 {
		if StringInSlice(e, s2) {
			return true
		}
	}
	return false
}

func StringInMapSlice(key string, maplist map[string][]string) bool {
	for _, list := range maplist {
		for _, entry := range list {
			if entry == key {
				return true
			}
		}
	}
	return false
}

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func GetFileAge(file string) float64 {
	if Exists(file) {
		var err error
		var fi os.FileInfo
		if fi, err = os.Stat(file); err == nil {

			mtime := fi.ModTime()
			interval := time.Since(mtime)
			age := interval.Seconds()

			return age
		}
		return 0
	}
	return 0
}
