package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/quay/claircore/internal/scanner"

	"github.com/jmoiron/sqlx"
)

const (
	selectScannerID = `SELECT id FROM scanner WHERE name = $1 AND version = $2;`
	// artifacts for a layer are always persisted via a transaction thus finding a single
	// artifact matching the name, version, and layer hash will signify a layer
	// has been scanned by the scanner in question.
	selectScanArtifact = `SELECT layer_hash FROM scanartifact WHERE layer_hash = $1 AND scanner_id = $2 LIMIT 1;`
)

func layerScanned(ctx context.Context, db *sqlx.DB, hash string, scnr scanner.VersionedScanner) (bool, error) {
	// TODO Use passed-in Context.
	var scannerID int
	err := db.Get(&scannerID, selectScannerID, scnr.Name(), scnr.Version())
	if err != nil {
		if err == sql.ErrNoRows {
			// TODO: make error type to handle this case
			return false, fmt.Errorf("scanner name and version not found in store")
		}
		return false, err
	}

	var layerHash string
	err = db.Get(&layerHash, selectScanArtifact, hash, scannerID)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to select scanartifact with layer hash: %v", err)
	}

	return true, nil
}