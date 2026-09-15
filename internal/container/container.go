// Package container is the deterministic file archive xrplbak encrypts.
// Layout (all integers big-endian):
//
//	"XBC1" | u32 count | entries...
//	entry: u16 pathLen | path | u32 mode | u64 size | 32-byte sha256 | data
//
// Entries are sorted by path. No timestamps, owners, or symlinks, so the
// same files always produce the same bytes.
package container

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

var magic = []byte("XBC1")

// BlockLen is the padding unit and the on-chain chunk plaintext size.
const BlockLen = 960

// Entry is one file.
type Entry struct {
	Path string
	Mode uint32
	Data []byte
}

// SHA256 of the entry content, hex-free for callers to format.
func (e Entry) SHA256() [32]byte { return sha256.Sum256(e.Data) }

// Encode serializes entries in canonical order.
func Encode(entries []Entry) ([]byte, error) {
	sorted := append([]Entry{}, entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Path == sorted[i-1].Path {
			return nil, fmt.Errorf("duplicate path %q", sorted[i].Path)
		}
	}
	b := append([]byte{}, magic...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(sorted)))
	for _, e := range sorted {
		if len(e.Path) == 0 || len(e.Path) > 65535 {
			return nil, fmt.Errorf("bad path length for %q", e.Path)
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(e.Path)))
		b = append(b, e.Path...)
		b = binary.BigEndian.AppendUint32(b, e.Mode&0o7777)
		b = binary.BigEndian.AppendUint64(b, uint64(len(e.Data)))
		sum := e.SHA256()
		b = append(b, sum[:]...)
		b = append(b, e.Data...)
	}
	return b, nil
}

// Decode parses and verifies per-entry hashes.
func Decode(b []byte) ([]Entry, error) {
	if len(b) < 8 || !bytes.Equal(b[:4], magic) {
		return nil, errors.New("not an xrplbak container")
	}
	r := bytes.NewReader(b[4:])
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	var out []Entry
	for i := uint32(0); i < count; i++ {
		var plen uint16
		if err := binary.Read(r, binary.BigEndian, &plen); err != nil {
			return nil, fmt.Errorf("container truncated at entry %d", i)
		}
		path := make([]byte, plen)
		var mode uint32
		var size uint64
		var sum [32]byte
		if _, err := io.ReadFull(r, path); err != nil {
			return nil, fmt.Errorf("container truncated at entry %d", i)
		}
		if err := binary.Read(r, binary.BigEndian, &mode); err != nil {
			return nil, fmt.Errorf("container truncated at entry %d", i)
		}
		if err := binary.Read(r, binary.BigEndian, &size); err != nil {
			return nil, fmt.Errorf("container truncated at entry %d", i)
		}
		if _, err := io.ReadFull(r, sum[:]); err != nil {
			return nil, fmt.Errorf("container truncated at entry %d", i)
		}
		if size > uint64(r.Len()) {
			return nil, fmt.Errorf("container truncated inside %q", path)
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		if sha256.Sum256(data) != sum {
			return nil, fmt.Errorf("hash mismatch for %q", path)
		}
		out = append(out, Entry{Path: string(path), Mode: mode, Data: data})
	}
	if r.Len() != 0 {
		return nil, errors.New("container has trailing bytes")
	}
	return out, nil
}

// Pack compresses and pads to a BlockLen multiple. The last two bytes hold
// the pad length (1..BlockLen) so Unpack can strip it.
func Pack(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	c := buf.Bytes()
	pad := BlockLen - (len(c)+2)%BlockLen
	if pad == BlockLen {
		pad = 0
	}
	out := append(c, make([]byte, pad)...)
	return binary.BigEndian.AppendUint16(out, uint16(pad+2)), nil
}

// Unpack reverses Pack.
func Unpack(packed []byte) ([]byte, error) {
	if len(packed) < 2 || len(packed)%BlockLen != 0 {
		return nil, errors.New("packed data is not a whole number of blocks")
	}
	pad := int(binary.BigEndian.Uint16(packed[len(packed)-2:]))
	if pad < 2 || pad > len(packed) {
		return nil, errors.New("bad padding")
	}
	c := packed[:len(packed)-pad]
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(c)))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return raw, nil
}
