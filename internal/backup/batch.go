package backup

import (
	"errors"

	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/dump"
)

func (s *Submitter) submitBatched(*Plan, map[string]dump.Tx, map[[crypto.ManifestNonceLen]byte]map[uint16]landed) error {
	return errors.New("batched submit is not built")
}

func splitBatches(n int) []int { return []int{n} }
