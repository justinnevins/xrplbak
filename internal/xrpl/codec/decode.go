package codec

import (
	"errors"
	"fmt"
)

// Deserialize parses a blob produced by Serialize. It understands only the
// fields this tool emits; anything else is an error. Used by tests and by
// the offline fake, never on the submit path.
func Deserialize(b []byte) (*Tx, error) {
	tx := &Tx{}
	r := &reader{b: b}
	for !r.done() {
		typ, field, err := r.header()
		if err != nil {
			return nil, err
		}
		switch {
		case typ == 1 && field == 2:
			v, err := r.take(2)
			if err != nil {
				return nil, err
			}
			tx.Type = uint16(v[0])<<8 | uint16(v[1])
		case typ == 2:
			v, err := r.u32()
			if err != nil {
				return nil, err
			}
			switch field {
			case 2:
				tx.Flags = v
			case 4:
				tx.Sequence = v
			case 27:
				tx.LastLedgerSequence = v
			default:
				return nil, fmt.Errorf("unknown UInt32 field %d", field)
			}
		case typ == 6 && field == 8:
			v, err := r.take(8)
			if err != nil {
				return nil, err
			}
			var d uint64
			for _, c := range v {
				d = d<<8 | uint64(c)
			}
			tx.FeeDrops = d &^ (1 << 62)
		case typ == 7:
			v, err := r.vl()
			if err != nil {
				return nil, err
			}
			switch field {
			case 3:
				tx.SigningPubKey = v
			case 4:
				tx.TxnSignature = v
			case 5:
				tx.URI = v
			case 26:
				tx.DIDDocument = v
			case 27:
				tx.Data = v
			default:
				return nil, fmt.Errorf("unknown Blob field %d", field)
			}
		case typ == 8 && field == 1:
			v, err := r.vl()
			if err != nil {
				return nil, err
			}
			tx.Account = v
		case typ == 15 && field == 9:
			memos, err := r.memos()
			if err != nil {
				return nil, err
			}
			tx.Memos = memos
		default:
			return nil, fmt.Errorf("unknown field type %d field %d", typ, field)
		}
	}
	return tx, nil
}

type reader struct {
	b []byte
	i int
}

func (r *reader) done() bool { return r.i >= len(r.b) }

func (r *reader) take(n int) ([]byte, error) {
	if r.i+n > len(r.b) {
		return nil, errors.New("blob truncated")
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v, nil
}

func (r *reader) header() (typ, field int, err error) {
	h, err := r.take(1)
	if err != nil {
		return 0, 0, err
	}
	typ, field = int(h[0]>>4), int(h[0]&0x0F)
	if typ == 0 {
		t, err := r.take(1)
		if err != nil {
			return 0, 0, err
		}
		typ = int(t[0])
	}
	if field == 0 {
		f, err := r.take(1)
		if err != nil {
			return 0, 0, err
		}
		field = int(f[0])
	}
	return typ, field, nil
}

func (r *reader) u32() (uint32, error) {
	v, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3]), nil
}

func (r *reader) vl() ([]byte, error) {
	l, err := r.take(1)
	if err != nil {
		return nil, err
	}
	n := int(l[0])
	switch {
	case n <= 192:
	case n <= 240:
		l2, err := r.take(1)
		if err != nil {
			return nil, err
		}
		n = 193 + (n-193)<<8 + int(l2[0])
	default:
		l2, err := r.take(2)
		if err != nil {
			return nil, err
		}
		n = 12481 + (n-241)<<16 + int(l2[0])<<8 + int(l2[1])
	}
	return r.take(n)
}

func (r *reader) memos() ([]Memo, error) {
	var out []Memo
	for {
		h, err := r.take(1)
		if err != nil {
			return nil, err
		}
		if h[0] == 0xF1 {
			return out, nil
		}
		if h[0] != 0xEA {
			return nil, errors.New("bad memo object header")
		}
		var m Memo
		for {
			f, err := r.take(1)
			if err != nil {
				return nil, err
			}
			if f[0] == 0xE1 {
				break
			}
			v, err := r.vl()
			if err != nil {
				return nil, err
			}
			switch f[0] {
			case 0x7C:
				m.Type = v
			case 0x7D:
				m.Data = v
			case 0x7E:
				m.Format = v
			default:
				return nil, errors.New("bad memo field")
			}
		}
		out = append(out, m)
	}
}
