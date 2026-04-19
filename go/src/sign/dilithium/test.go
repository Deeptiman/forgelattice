package sign

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type HexBytes []byte

func (b HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(b))
}

func (b *HexBytes) UnmarshalJSON(data []byte) (err error) {
	var s string
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	*b, err = hex.DecodeString(strings.TrimPrefix(s, "0x"))
	return err
}

func gunzip(in []byte) ([]byte, error) {
	buf := bytes.NewBuffer(in)
	r, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// Like os.ReadFile, but gunzip first.
func ReadGzip(path string) ([]byte, error) {
	buf, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return gunzip(buf)
}
