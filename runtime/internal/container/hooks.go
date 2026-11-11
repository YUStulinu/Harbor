package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// runHooks runs hooks in order with the container state on their stdin. The first failure
// stops the sequence.
func runHooks(kind string, hooks []specs.Hook, st specs.State) error {
	in, err := json.Marshal(st)
	if err != nil {
		return err
	}
	for _, h := range hooks {
		ctx := context.Background()
		var cancel context.CancelFunc
		if h.Timeout != nil {
			if *h.Timeout <= 0 {
				return fmt.Errorf("%s hook %s: timeout must be positive", kind, h.Path)
			}
			ctx, cancel = context.WithTimeout(ctx, time.Duration(*h.Timeout)*time.Second)
		}
		cmd := exec.CommandContext(ctx, h.Path)
		if len(h.Args) > 0 {
			cmd.Args = h.Args
		} else {
			cmd.Args = []string{h.Path}
		}
		cmd.Env = h.Env
		cmd.Stdin = bytes.NewReader(in)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		if cancel != nil {
			cancel()
		}
		if err != nil {
			return fmt.Errorf("%s hook %s: %w: %s", kind, h.Path, err, bytes.TrimSpace(out.Bytes()))
		}
	}
	return nil
}
