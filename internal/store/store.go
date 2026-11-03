// Package store adalah ledger SQLite xyland: state hidup di sini,
// bukan di context window LLM (docs/12, P-1). Receipt grounding (docs/11, L-1)
// ditegakkan lewat tabel executions: finding wajib terikat execution_id.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

type Job struct {
	ID        string
	Target    string
	State     string
	CreatedAt time.Time
}

type Execution struct {
	ID       int64
	JobID    string
	Tool     string
	Args     string
	ExitCode int
	Note     string
	At       time.Time
}

type Asset struct {
	ID          int64
	JobID       string
	URL         string
	StatusCode  int
	Title       string
	Fingerprint string // ringkasan teks: server, cookie flags, dsb
	ExecutionID int64
}

type Finding struct {
	ID          int64
	JobID       string
	Class       string
	Title       string
	URL         string
	Severity    string
	Status      string // raw | confirmed | likely | false-positive | inconclusive
	Evidence    string
	PocPath     string
	ExecutionID int64
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{DB: db}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, target TEXT, state TEXT, created_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS executions(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, tool TEXT, args TEXT, exit_code INTEGER, note TEXT, at TEXT)`,
		`CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, url TEXT, status_code INTEGER, title TEXT, fingerprint TEXT, execution_id INTEGER)`,
		`CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, class TEXT, title TEXT, url TEXT, severity TEXT, status TEXT, evidence TEXT, poc_path TEXT, execution_id INTEGER)`,
		`CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, state TEXT, note TEXT, at TEXT)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return nil, fmt.Errorf("schema: %w", err)
		}
	}
	return s, nil
}

func (s *Store) CreateJob(id, target string) error {
	_, err := s.DB.Exec(`INSERT INTO jobs(id,target,state,created_at) VALUES(?,?,?,?)`,
		id, target, "SCOPE", time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) SetState(jobID, state string) error {
	_, err := s.DB.Exec(`UPDATE jobs SET state=? WHERE id=?`, state, jobID)
	return err
}

func (s *Store) GetJob(id string) (*Job, error) {
	row := s.DB.QueryRow(`SELECT id,target,state,created_at FROM jobs WHERE id=?`, id)
	var j Job
	var ca string
	if err := row.Scan(&j.ID, &j.Target, &j.State, &ca); err != nil {
		return nil, err
	}
	j.CreatedAt, _ = time.Parse(time.RFC3339, ca)
	return &j, nil
}

func (s *Store) RecordExecution(jobID, tool, args string, exitCode int, note string) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO executions(job_id,tool,args,exit_code,note,at) VALUES(?,?,?,?,?,?)`,
		jobID, tool, args, exitCode, note, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) AddAsset(a Asset) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO assets(job_id,url,status_code,title,fingerprint,execution_id) VALUES(?,?,?,?,?,?)`,
		a.JobID, a.URL, a.StatusCode, a.Title, a.Fingerprint, a.ExecutionID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) AddFinding(f Finding) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO findings(job_id,class,title,url,severity,status,evidence,poc_path,execution_id) VALUES(?,?,?,?,?,?,?,?,?)`,
		f.JobID, f.Class, f.Title, f.URL, f.Severity, f.Status, f.Evidence, f.PocPath, f.ExecutionID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateFindingStatus(id int64, status, pocPath string) error {
	_, err := s.DB.Exec(`UPDATE findings SET status=?, poc_path=? WHERE id=?`, status, pocPath, id)
	return err
}

func (s *Store) Findings(jobID string) ([]Finding, error) {
	rows, err := s.DB.Query(`SELECT id,job_id,class,title,url,severity,status,evidence,poc_path,execution_id FROM findings WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.JobID, &f.Class, &f.Title, &f.URL, &f.Severity, &f.Status, &f.Evidence, &f.PocPath, &f.ExecutionID); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) Assets(jobID string) ([]Asset, error) {
	rows, err := s.DB.Query(`SELECT id,job_id,url,status_code,title,fingerprint,execution_id FROM assets WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.JobID, &a.URL, &a.StatusCode, &a.Title, &a.Fingerprint, &a.ExecutionID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateFindingEvidence memperbarui teks bukti sebuah finding (mis. menambah path screenshot).
func (s *Store) UpdateFindingEvidence(id int64, evidence string) error {
	_, err := s.DB.Exec(`UPDATE findings SET evidence=? WHERE id=?`, evidence, id)
	return err
}

// LatestJobID mengembalikan id job terbaru selain yang dikecualikan ("" = tanpa kecuali).
func (s *Store) LatestJobID(except string) (string, error) {
	row := s.DB.QueryRow(`SELECT id FROM jobs WHERE id != ? ORDER BY created_at DESC LIMIT 1`, except)
	var id string
	err := row.Scan(&id)
	return id, err
}

func (s *Store) AddNote(jobID, state, note string) error {
	_, err := s.DB.Exec(`INSERT INTO notes(job_id,state,note,at) VALUES(?,?,?,?)`,
		jobID, state, note, time.Now().UTC().Format(time.RFC3339))
	return err
}
