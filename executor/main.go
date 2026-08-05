package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	workspace  = "/workspace"
	socketPath = "/run/execsock/exec.sock"
	// 512 MB /workspace tmpfs after base64 (~683 MB) + JSON envelope.
	maxRequestBytes = 700 << 20
	// bashUID/bashGID is the identity /exec drops bash into. Distinct from
	// the executor process's uid (1000) so ro /user-uploads can be enforced
	bashUID = 1001
	bashGID = 1001
)

// workspaceRoot is the *os.Root handle to /workspace shared by /read,
// /write, /snapshot, /restore. openat2(RESOLVE_BENEATH) rejects any
// path that escapes. /exec runs unsandboxed (cmd.Dir = workspace).
var workspaceRoot *os.Root

var execMu sync.Mutex

type execRequest struct {
	Command string `json:"command"`
}

type execResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

type readRequest struct {
	Path string `json:"path"`
}

type readResponse struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

type writeRequest struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
}

type writeResponse struct {
	Path string `json:"path"`
	Size int    `json:"size"`
}

func handleExec(w http.ResponseWriter, r *http.Request) {
	execMu.Lock()
	defer execMu.Unlock()

	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Command == "" {
		respondError(w, http.StatusBadRequest, "command is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", req.Command)
	cmd.Dir = workspace
	// Point HTTP clients at the egress proxy and its CA. Enforcement is the
	// kernel's job (the sandbox network is `egress: closed`); this only makes
	// well-behaved tooling take the route that gets recorded.
	cmd.Env = commandEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Put bash in its own process group so timeout / cancellation kills grandchildren.
		Setpgid:    true,
		Credential: &syscall.Credential{Uid: bashUID, Gid: bashGID},
	}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	stdoutFile, err := os.CreateTemp("/tmp", "exec-stdout-*")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "creating stdout capture: "+err.Error())
		return
	}
	defer stdoutFile.Close()
	_ = os.Remove(stdoutFile.Name())
	stderrFile, err := os.CreateTemp("/tmp", "exec-stderr-*")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "creating stderr capture: "+err.Error())
		return
	}
	defer stderrFile.Close()
	_ = os.Remove(stderrFile.Name())
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	err = cmd.Run()
	// Process-group cancellation is insufficient: setsid(2) lets descendants
	// escape it. All user commands run under an otherwise-unused UID, so killing
	// that UID after every execution provides a lifecycle boundary for detached
	// descendants too.
	if cleanupErr := killCommandProcesses(); cleanupErr != nil {
		// Exiting the container is the only safe fallback: the runtime tears down
		// its PID namespace, so cleanup can never fail open.
		log.Fatalf("executor: command descendant cleanup failed: %v", cleanupErr)
	}
	stdout, stdoutErr := readCapture(stdoutFile)
	stderr, stderrErr := readCapture(stderrFile)
	if stdoutErr != nil || stderrErr != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("reading command output: stdout=%v stderr=%v", stdoutErr, stderrErr))
		return
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		respondJSON(w, http.StatusOK, execResponse{
			Stderr:   "command timed out (30s)",
			ExitCode: -1,
		})
		return
	}

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			respondError(w, http.StatusInternalServerError, "exec failed: "+err.Error())
			return
		}
	}

	respondJSON(w, http.StatusOK, execResponse{
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		ExitCode: exitCode,
	})
}

func readCapture(f *os.File) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

func killCommandProcesses() error {
	deadline := time.Now().Add(time.Second)
	cleanScans := 0
	for time.Now().Before(deadline) {
		pids, err := commandPIDs()
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			cleanScans++
			if cleanScans == 2 {
				return nil
			}
		} else {
			cleanScans = 0
			for _, pid := range pids {
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					return fmt.Errorf("killing pid %d: %w", pid, err)
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("command processes remained after SIGKILL")
}

func commandPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if err != nil {
			continue
		}
		uidMatch := false
		zombie := false
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "Uid:" {
				uid, parseErr := strconv.ParseUint(fields[1], 10, 32)
				uidMatch = parseErr == nil && uid == bashUID
			}
			if len(fields) >= 2 && fields[0] == "State:" {
				zombie = fields[1] == "Z"
			}
		}
		if uidMatch && !zombie {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func handleRead(w http.ResponseWriter, r *http.Request) {
	var req readRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	rel, err := resolveP(req.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	info, err := workspaceRoot.Stat(rel)
	if err != nil {
		if os.IsNotExist(err) {
			respondError(w, http.StatusNotFound, fmt.Sprintf("file not found: %s", req.Path))
			return
		}
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if info.IsDir() {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("path is a directory: %s", req.Path))
		return
	}

	data, err := workspaceRoot.ReadFile(rel)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, readResponse{
		Path:     req.Path,
		Contents: base64.StdEncoding.EncodeToString(data),
	})
}

func handleWrite(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var req writeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			respondError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("payload exceeds %d bytes", maxErr.Limit))
			return
		}
		respondError(w, http.StatusBadRequest, "invalid json")
		return
	}

	rel, err := resolveP(req.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Contents)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid base64 contents")
		return
	}

	if err := workspaceRoot.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := workspaceRoot.WriteFile(rel, data, 0o644); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, writeResponse{
		Path: req.Path,
		Size: len(data),
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		log.Fatalf("open workspace root %s: %v", workspace, err)
	}
	defer root.Close()
	workspaceRoot = root

	uRoot, err := os.OpenRoot(uploadsDir)
	if err != nil {
		log.Fatalf("open uploads root %s: %v", uploadsDir, err)
	}
	defer uRoot.Close()
	uploadsRoot = uRoot

	mux := http.NewServeMux()
	mux.HandleFunc("/exec", handleExec)
	mux.HandleFunc("/read", handleRead)
	mux.HandleFunc("/write", handleWrite)
	mux.HandleFunc("/snapshot", handleSnapshot)
	mux.HandleFunc("/restore", handleRestore)
	mux.HandleFunc("/sync-uploads/manifest", handleSyncUploadsManifest)
	mux.HandleFunc("/sync-uploads/blobs", handleSyncUploadsBlobs)
	mux.HandleFunc("/session/init", handleSessionInit)
	mux.HandleFunc("/health", handleHealth)

	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("removing stale socket: %v", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen unix %s: %v", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	log.Printf("executor listening on unix:%s", socketPath)
	log.Fatal(http.Serve(listener, mux))
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}

// resolveP strips an optional /workspace/ prefix; "..", escapes, and
// empty paths are rejected downstream by *os.Root.
func resolveP(p string) (string, error) {
	if p == "" {
		return "", errors.New("path is required")
	}
	if filepath.IsAbs(p) {
		rel, err := filepath.Rel(workspace, p)
		if err != nil {
			return "", fmt.Errorf("path outside %s: %s", workspace, p)
		}
		return rel, nil
	}
	return p, nil
}
