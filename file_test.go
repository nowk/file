package file

import (
	"fmt"
	"testing"

	"gopkg.in/mgo.v2/bson"
	"gopkg.in/nowk/assert.v2"
)

func init() {
	AwsSecretKey = []byte("awssecretkey")
}

const (
	objectId = "54dc05f351d4e459b7000005"
	path     = "/aws3_bucket/abcd/large.txt"
)

func TestParsesFilenameFromPath(t *testing.T) {
	assert.Equal(t, "large.txt", New(path, "text/plain", 0).Name)
}

func TestPathIsAlwaysAbsolute(t *testing.T) {
	assert.Equal(t, "/", string(New("path/to/file.ext", "", 0).Path[0]))
	assert.Equal(t, "/", string(New("/path/to/file.ext", "", 0).Path[0]))
}

func TestFilenameInPathShouldBeBsonID(t *testing.T) {
	path := "/path/to/file with spaces.jpg"
	f := New(path, "", 0, func(f *File) {
		f.ID = bson.ObjectIdHex(objectId)
	})
	assert.Equal(t, "file with spaces.jpg", f.Name)
	assert.Equal(t, fmt.Sprintf("/path/to/%s.jpg", objectId), f.Path)
}

func TestPUTPayloadForSign(t *testing.T) {
	f := New(path, "text/plain", 0, func(f *File) {
		f.Expires = 3600
		f.ID = bson.ObjectIdHex(objectId)
	})
	p := f.Payload(PUT)
	exp := []string{
		"PUT",
		"",
		"text/plain",
		"3600",
		"x-amz-acl:private",
		fmt.Sprintf("/aws3_bucket/abcd/%s%s", objectId, ".txt"),
	}
	assert.Equal(t, exp, p)
}

func TestPUTSignature(t *testing.T) {
	f := New(path, "text/plain", 0, func(f *File) {
		f.Expires = 3600
		f.ID = bson.ObjectIdHex(objectId)
	})
	b, err := Sign(PUT, f)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "e2PHVjwJL7X8zo/aw5ARpz9ljF4=", string(b))
}

func TestGETPayloadForSign(t *testing.T) {
	f := New(path, "text/plain", 0, func(f *File) {
		f.Expires = 3600
		f.ID = bson.ObjectIdHex(objectId)
	})
	p := f.Payload(GET)
	exp := []string{
		"GET",
		"",
		"",
		"3600",
		fmt.Sprintf("/aws3_bucket/abcd/%s%s", objectId, ".txt"),
	}
	assert.Equal(t, exp, p)
}

func TestGETSignature(t *testing.T) {
	f := New(path, "text/plain", 0, func(f *File) {
		f.Expires = 3600
		f.ID = bson.ObjectIdHex(objectId)
	})
	b, err := Sign(GET, f)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "UrqygIQkXzKhNtldnhMLdY4+RMg=", string(b))
}
