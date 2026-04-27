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

// migrate creates the schema if it doesn't exist.
func (idx *Index) migrate() error {
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
			(file_path, start_time, end_time, interface, packet_count, byte_count, alert_driven, community_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		file.FilePath, file.StartTime, file.EndTime, file.Interface,
		file.PacketCount, file.ByteCount, alertDriven, file.CommunityID,
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

// QueryByTimeRange returns all PCAP files whose time range overlaps [start, end].
func (idx *Index) QueryByTimeRange(start, end int64) ([]PcapFile, error) {
	rows, err := idx.db.Query(`
		SELECT id, file_path, start_time, end_time, interface, packet_count, byte_count, alert_driven, community_id
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
		SELECT id, file_path, start_time, end_time, interface, packet_count, byte_count, alert_driven, community_id
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
		SELECT id, file_path, start_time, end_time, interface, packet_count, byte_count, alert_driven, community_id
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
		if err := rows.Scan(&f.ID, &f.FilePath, &f.StartTime, &f.EndTime,
			&f.Interface, &f.PacketCount, &f.ByteCount, &alertDriven, &f.CommunityID); err != nil {
			return nil, fmt.Errorf("scan pcap file row: %w", err)
		}
		f.AlertDriven = alertDriven != 0
		files = append(files, f)
	}
	return files, rows.Err()
}
