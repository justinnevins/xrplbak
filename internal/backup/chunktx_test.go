package backup

import "github.com/justinnevins/xrplbak/internal/xrpl/codec"

// chunkTx builds the carrier transaction for chunk i.
func chunkTx(p *Plan, i int) *codec.Tx {
	return &codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{p.ChunkMemos[i]}}
}
