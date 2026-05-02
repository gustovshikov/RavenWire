package pcap

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// PcapFile represents a single PCAP file entry in the index.
type PcapFile struct {
	ID          int64  `json:"id"`
	FilePath    string `json:"file_path"`
	StartTime   int64  `json:"start_time"` // Unix ms
	EndTime     int64  `json:"end_time"`   // Unix ms
	Interface   string `json:"interface"`
	PacketCount int64  `json:"packet_count"`
	ByteCount   int64  `json:"byte_count"`
	AlertDriven bool   `json:"alert_driven"`
	CommunityID string `json:"community_id,omitempty"`

	// Evidence-grade metadata fields (Requirement 9.1, 9.7)
	Sha256Hash                 string `json:"sha256_hash,omitempty"`
	FileSizeBytes              int64  `json:"file_size_bytes,omitempty"`
	SensorID                   string `json:"sensor_id,omitempty"`
	AlertSID                   string `json:"alert_sid,omitempty"`
	AlertSignature             string `json:"alert_signature,omitempty"`
	AlertUUID                  string `json:"alert_uuid,omitempty"`
	SrcIP                      string `json:"src_ip,omitempty"`
	DstIP                      string `json:"dst_ip,omitempty"`
	SrcPort                    int    `json:"src_port,omitempty"`
	DstPort                    int    `json:"dst_port,omitempty"`
	Proto                      string `json:"proto,omitempty"`
	ZeekUID                    string `json:"zeek_uid,omitempty"`
	CaptureInterface           string `json:"capture_interface,omitempty"`
	CarveReason                string `json:"carve_reason,omitempty"`
	RequestedBy                string `json:"requested_by,omitempty"`
	CreatedAtMs                int64  `json:"created_at_ms,omitempty"`
	RetentionExpiresAtMs       int64  `json:"retention_expires_at_ms,omitempty"`
	ChainOfCustodyManifestPath string `json:"chain_of_custody_manifest_path,omitempty"`
}

// Index manages the SQLite PCAP file index.
type Index struct {
	db *sql.DB
}

// OpenIndex opens (or creates) the SQLite PCAP index at the given path.
func OpenIndex(dbPath string) (*Index, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create index dir: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite db %s: %w", dbPath, err)
	}

	idx := &Index{db: db}
	if err := idx.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate db: %w", err)
	}

	return idx, nil
}

// migrate creates the schema if it doesn't exist and applies backward-compatible
// schema migrations for new columns (Requirement 9.7).
func (idx *Index) migrate() error {
	// Original schema creation.
	_, err := idx.db.Exec(`
		CREATE TABLE IF NOT EXISTS pcap_files (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			file_path    TEXT NOT NULL,
			start_time   INTEGER NOT NULL,
			end_time     INTEGER NOT NULL,
			interface    TEXT NOT NULL,
			packet_count INTEGER NOT NULL,
			byte_count   INTEGER NOT NULL,
			alert_driven INTEGER DEFAULT 0,
			community_id TEXT DEFAULT ''
		);

		CREATE INDEX IF NOT EXISTS idx_file_time_range
			ON pcap_files(start_time, end_time);

		CREATE INDEX IF NOT EXISTS idx_community_id
			ON pcap_files(community_id)
			WHERE community_id != '';
	`)
	if err != nil {
		return err
	}

	// Evidence-grade metadata columns (Requirement 9.1, 9.7).
	// Each ALTER TABLE is idempotent: we check if the column exists first.
	newColumns := []struct {
		name    string
		colType string
	}{
		{"sha256_hash", "TEXT DEFAULT NULL"},
		{"file_size_bytes", "INTEGER DEFAULT NULL"},
		{"sensor_id", "TEXT DEFAULT NULL"},
		{"alert_sid", "TEXT DEFAULT NULL"},
		{"alert_signature", "TEXT DEFAULT NULL"},
		{"alert_uuid", "TEXT DEFAULT NULL"},
		{"src_ip", "TEXT DEFAULT NULL"},
		{"dst_ip", "TEXT DEFAULT NULL"},
		{"src_port", "INTEGER DEFAULT NULL"},
		{"dst_port", "INTEGER DEFAULT NULL"},
		{"proto", "TEXT DEFAULT NULL"},
		{"zeek_uid", "TEXT DEFAULT NULL"},
		{"capture_interface", "TEXT DEFAULT NULL"},
		{"carve_reason", "TEXT DEFAULT NULL"},
		{"requested_by", "TEXT DEFAULT NULL"},
		{"created_at_ms", "INTEGER DEFAULT NULL"},
		{"retention_expires_at_ms", "INTEGER DEFAULT NULL"},
		{"chain_of_custody_manifest_path", "TEXT DEFAULT NULL"},
	}

	for _, col := range newColumns {
		if err := idx.addColumnIfNotExists(col.name, col.colType); err != nil {
			return fmt.Errorf("add column %s: %w", col.name, err)
		}
	}

	// Index for retention pruning queries (Requirement 9.5).
	_, err = idx.db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_retention_expires
			ON pcap_files(retention_expires_at_ms)
			WHERE retention_expires_at_ms IS NOT NULL;
	`)
	return err
}

// addColumnIfNotExists adds a column to pcap_files if it doesn't already exist.
// SQLite doesn't support IF NOT EXISTS for ALTER TABLE ADD COLUMN, so we check
// the table_info pragma first.
func (idx *Index) addColumnIfNotExists(name, colType string) error {
	rows, err := idx.db.Query("PRAGMA table_info(pcap_files)")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var cname, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &cname, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if cname == name {
			return nil // column already exists
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = idx.db.Exec(fmt.Sprintf("ALTER TABLE pcap_files ADD COLUMN %s %s", name, colType))
	return err
}

// Insert adds a new PCAP file entry to the index.
func (idx *Index) Insert(file PcapFile) (int64, error) {
	alertDriven := 0
	if file.AlertDriven {
		alertDriven = 1
	}

	result, err := idx.db.Exec(`
		INSERT INTO pcap_files
			(file_path, start_time, end_time, interface, packet_count, byte_count, alert_driven, community_id,
			 sha256_hash, file_size_bytes, sensor_id, alert_sid, alert_signature, alert_uuid,
			 src_ip, dst_ip, src_port, dst_port, proto, zeek_uid, capture_interface,
			 carve_reason, requested_by, created_at_ms, retention_expires_at_ms,
			 chain_of_custody_manifest_path)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?,
		        ?, ?, ?, ?, ?, ?,
		        ?, ?, ?, ?, ?, ?, ?,
		        ?, ?, ?, ?,
		        ?)`,
		file.FilePath, file.StartTime, file.EndTime, file.Interface,
		file.PacketCount, file.ByteCount, alertDriven, file.CommunityID,
		nullableString(file.Sha256Hash), nullableInt64(file.FileSizeBytes),
		nullableString(file.SensorID), nullableString(file.AlertSID),
		nullableString(file.AlertSignature), nullableString(file.AlertUUID),
		nullableString(file.SrcIP), nullableString(file.DstIP),
		nullableInt(file.SrcPort), nullableInt(file.DstPort),
		nullableString(file.Proto), nullableString(file.ZeekUID),
		nullableString(file.CaptureInterface),
		nullableString(file.CarveReason), nullableString(file.RequestedBy),
		nullableInt64(file.CreatedAtMs), nullableInt64(file.RetentionExpiresAtMs),
		nullableString(file.ChainOfCustodyManifestPath),
	)
	if err != nil {
		return 0, fmt.Errorf("insert pcap file: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// nullableString returns nil if s is empty, otherwise s. This ensures empty
// strings are stored as NULL in the database for the new nullable columns.
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullableInt64 returns nil if v is 0, otherwise v.
func nullableInt64(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

// nullableInt returns nil if v is 0, otherwise v.
func nullableInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

// allColumns is the full list of columns selected in all queries.
const allColumns = `id, file_path, start_time, end_time, interface, packet_count, byte_count, alert_driven, community_id,
	sha256_hash, file_size_bytes, sensor_id, alert_sid, alert_signature, alert_uuid,
	src_ip, dst_ip, src_port, dst_port, proto, zeek_uid, capture_interface,
	carve_reason, requested_by, created_at_ms, retention_expires_at_ms,
	chain_of_custody_manifest_path`

// QueryByTimeRange returns all PCAP files whose time range overlaps [start, end].
func (idx *Index) QueryByTimeRange(start, end int64) ([]PcapFile, error) {
	rows, err := idx.db.Query(`
		SELECT `+allColumns+`
		FROM pcap_files
		WHERE start_time <= ? AND end_time >= ?
		ORDER BY start_time ASC`,
		end, start,
	)
	if err != nil {
		return nil, fmt.Errorf("query by time range: %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}

// QueryByCommunityID returns all PCAP files associated with a Community ID.
func (idx *Index) QueryByCommunityID(communityID string) ([]PcapFile, error) {
	rows, err := idx.db.Query(`
		SELECT `+allColumns+`
		FROM pcap_files
		WHERE community_id = ?
		ORDER BY start_time ASC`,
		communityID,
	)
	if err != nil {
		return nil, fmt.Errorf("query by community_id: %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}

// QueryByFilePath returns all PCAP files matching the given file path.
func (idx *Index) QueryByFilePath(filePath string) ([]PcapFile, error) {
	rows, err := idx.db.Query(`
		SELECT `+allColumns+`
		FROM pcap_files
		WHERE file_path = ?
		ORDER BY start_time ASC`,
		filePath,
	)
	if err != nil {
		return nil, fmt.Errorf("query by file_path: %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}

// GetByID returns a single PCAP file entry by its ID.
func (idx *Index) GetByID(id int64) (*PcapFile, error) {
	rows, err := idx.db.Query(`
		SELECT `+allColumns+`
		FROM pcap_files
		WHERE id = ?`,
		id,
	)
	if err != nil {
		return nil, fmt.Errorf("get by id %d: %w", id, err)
	}
	defer rows.Close()

	files, err := scanFiles(rows)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("pcap file %d not found", id)
	}
	return &files[0], nil
}

// DeleteByID removes a PCAP file entry from the index by ID.
func (idx *Index) DeleteByID(id int64) error {
	_, err := idx.db.Exec("DELETE FROM pcap_files WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete pcap file %d: %w", id, err)
	}
	return nil
}

// OldestFiles returns the n oldest PCAP files by start_time.
func (idx *Index) OldestFiles(n int) ([]PcapFile, error) {
	rows, err := idx.db.Query(`
		SELECT `+allColumns+`
		FROM pcap_files
		ORDER BY start_time ASC
		LIMIT ?`,
		n,
	)
	if err != nil {
		return nil, fmt.Errorf("query oldest files: %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}

// Count returns the total number of indexed PCAP files.
func (idx *Index) Count() (int64, error) {
	var count int64
	err := idx.db.QueryRow("SELECT COUNT(*) FROM pcap_files").Scan(&count)
	return count, err
}

// Close closes the database connection.
func (idx *Index) Close() error {
	return idx.db.Close()
}

func scanFiles(rows *sql.Rows) ([]PcapFile, error) {
	var files []PcapFile
	for rows.Next() {
		var f PcapFile
		var alertDriven int

		// Nullable columns use sql.Null* types for backward compatibility (Requirement 9.7).
		var sha256Hash, sensorID, alertSID, alertSignature, alertUUID sql.NullString
		var srcIP, dstIP, proto, zeekUID, captureInterface sql.NullString
		var carveReason, requestedBy, custodyPath sql.NullString
		var fileSizeBytes, createdAtMs, retentionExpiresAtMs sql.NullInt64
		var srcPort, dstPort sql.NullInt64

		if err := rows.Scan(
			&f.ID, &f.FilePath, &f.StartTime, &f.EndTime,
			&f.Interface, &f.PacketCount, &f.ByteCount, &alertDriven, &f.CommunityID,
			&sha256Hash, &fileSizeBytes, &sensorID, &alertSID, &alertSignature, &alertUUID,
			&srcIP, &dstIP, &srcPort, &dstPort, &proto, &zeekUID, &captureInterface,
			&carveReason, &requestedBy, &createdAtMs, &retentionExpiresAtMs,
			&custodyPath,
		); err != nil {
			return nil, fmt.Errorf("scan pcap file row: %w", err)
		}

		f.AlertDriven = alertDriven != 0
		f.Sha256Hash = sha256Hash.String
		f.FileSizeBytes = fileSizeBytes.Int64
		f.SensorID = sensorID.String
		f.AlertSID = alertSID.String
		f.AlertSignature = alertSignature.String
		f.AlertUUID = alertUUID.String
		f.SrcIP = srcIP.String
		f.DstIP = dstIP.String
		f.SrcPort = int(srcPort.Int64)
		f.DstPort = int(dstPort.Int64)
		f.Proto = proto.String
		f.ZeekUID = zeekUID.String
		f.CaptureInterface = captureInterface.String
		f.CarveReason = carveReason.String
		f.RequestedBy = requestedBy.String
		f.CreatedAtMs = createdAtMs.Int64
		f.RetentionExpiresAtMs = retentionExpiresAtMs.Int64
		f.ChainOfCustodyManifestPath = custodyPath.String

		files = append(files, f)
	}
	return files, rows.Err()
}

// QueryByRetentionExpired returns all PCAP files whose retention has expired.
// An entry is expired when retention_expires_at_ms is set (not null, > 0) and
// the current time (nowMs) exceeds it. Used by the retention pruning cycle
// (Requirement 9.5).
func (idx *Index) QueryByRetentionExpired(nowMs int64) ([]PcapFile, error) {
	rows, err := idx.db.Query(`
		SELECT `+allColumns+`
		FROM pcap_files
		WHERE retention_expires_at_ms IS NOT NULL
		  AND retention_expires_at_ms > 0
		  AND retention_expires_at_ms <= ?
		ORDER BY retention_expires_at_ms ASC`,
		nowMs,
	)
	if err != nil {
		return nil, fmt.Errorf("query by retention expired: %w", err)
	}
	defer rows.Close()

	return scanFiles(rows)
}
