package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// ---- subprocess wire protocol ----

type command struct {
	Cmd         string `json:"cmd"`
	Seed        string `json:"seed,omitempty"`
	MessageHex  string `json:"message_hex,omitempty"`
	IsBroadcast bool   `json:"is_broadcast,omitempty"`
	WireHex     string `json:"wire_hex,omitempty"`
}

type event struct {
	Event       string `json:"event"`
	IsBroadcast bool   `json:"is_broadcast,omitempty"`
	WireHex     string `json:"wire_hex,omitempty"`
	Message     string `json:"message,omitempty"`
	RHex        string `json:"r_hex,omitempty"`
	SHex        string `json:"s_hex,omitempty"`
}

type historicalPeer struct {
	cmd    *exec.Cmd
	stdin  *json.Encoder
	stdout *bufio.Scanner
}

func spawnHistoricalPeer(dir string) (*historicalPeer, error) {
	cmd := exec.Command("go", "run", "-mod=readonly", "./main.go")
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	return &historicalPeer{cmd: cmd, stdin: json.NewEncoder(stdin), stdout: scanner}, nil
}

func (h *historicalPeer) send(c command) error {
	return h.stdin.Encode(c)
}

// readTurn reads events until (and excluding) a "turn_done" sentinel.
func (h *historicalPeer) readTurn() ([]event, error) {
	var events []event
	for h.stdout.Scan() {
		line := h.stdout.Bytes()
		if len(line) == 0 {
			continue
		}
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			return events, fmt.Errorf("decode historical event: %w", err)
		}
		if e.Event == "turn_done" {
			return events, nil
		}
		events = append(events, e)
	}
	return events, fmt.Errorf("historical subprocess closed stdout before turn_done")
}

func (h *historicalPeer) quit() {
	_ = h.send(command{Cmd: "quit"})
	_ = h.cmd.Wait()
}
