package file

import (
	"crypto/sha1"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nowk/co"
	"gopkg.in/mgo.v2/bson"
)

var (
	AwsAccessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	AwsSecretKey = []byte(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	AwsRegion    = os.Getenv("AWS_REGION")

	expwindow = 1 * time.Hour
)

type File struct {
	ID   bson.ObjectId `bson:"-" json:"-"`
	Name string        `json:"name"`
	Type string        `json:"type"`
	Size int64         `json:"size"`
	Path string        `json:"path"`

	Bucket  string `bson:"bucket,omitempty" json:"bucket"`
	ACL     string `bson:"-" json:"acl"`
	Expires int64  `bson:"-" json:"expires"`
}

func tNow() time.Time {
	return time.Now()
}

func New(path, mime string, size int64, opts ...func(*File)) *File {
	f := &File{
		ID:   bson.NewObjectId(),
		Type: mime,
		Size: size,

		// set defaults
		ACL:     "private",
		Expires: tNow().Add(expwindow).Unix(),
	}
	for _, v := range opts {
		v(f)
	}
	f.parsePath(path)
	return f
}

// parsePath parses the path and returns a generated url to PUT to S3
// It replaces the original filename with a bson id to avoid issues with file
// name escaping
func (f *File) parsePath(path string) {
	n := filepath.Base(path)
	e := filepath.Ext(n)
	d := filepath.Dir(path)

	f.Name = n
	f.Path = filepath.Join("/", d, fmt.Sprintf("%s%s", f.ID.Hex(), e))
}

type Method string

var (
	GET Method = "GET"
	PUT Method = "PUT"
)

func (f *File) Payload(meth Method) []string {
	p := []string{
		string(meth),
		"",
		"",
		f.expiresStr(),
		f.Path,
	}

	// PUT signatures require additional data
	if meth == PUT {
		p[2] = f.Type

		// Save on some garbage https://github.com/golang/go/wiki/SliceTricks
		i := 4
		p = append(p, "")
		copy(p[i+1:], p[i:])
		p[i] = f.aclHeader()
	}

	return p
}

func (f *File) expiresStr() string {
	if f.ACL == "public" {
		return ""
	}

	if f.Expires == 0 {
		f.Expires = tNow().Add(expwindow).Unix()
	}

	return strconv.FormatInt(f.Expires, 10)
}

func (f File) aclHeader() string {
	return "x-amz-acl:" + f.ACL
}

func (f File) PutURL() (string, error) {
	return f.SignedURL(PUT)
}

func (f File) GetURL() (string, error) {
	return f.SignedURL(GET)
}

func regionHost() string {
	if AwsRegion == "" {
		return "s3.amazonaws.com"
	}

	return fmt.Sprintf("s3-%s.amazonaws.com", AwsRegion)
}

func (f *File) SignedURL(meth Method) (string, error) {
	if f.Path == "" {
		return "", nil
	}

	b64, err := Sign(meth, f)
	if err != nil {
		return "", err
	}

	q := url.Values{}
	q.Add("AWSAccessKeyId", AwsAccessKey)
	q.Add("Expires", f.expiresStr())
	q.Add("Signature", string(b64))

	u := url.URL{
		Scheme:   "https",
		Host:     regionHost(),
		Path:     f.Path,
		RawQuery: q.Encode(),
	}
	return u.String(), nil
}

// cosigner implements co.Messenger
type cosigner []byte

func (c cosigner) Message() ([]byte, error) {
	return c, nil
}

// Sign signs the file based on the required method and returns the Base64 of
// the signed bytes
func Sign(meth Method, f *File) ([]byte, error) {
	c := cosigner(strings.Join(f.Payload(meth), "\n"))
	b, err := co.Sign(c, sha1.New, AwsSecretKey)
	if err != nil {
		return nil, err
	}
	return b.Base64()
}
