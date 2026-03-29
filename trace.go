package privacy

import (
	"context"
	"io"
	"sync"
	"time"
)

// traceable presents an internal Protector wrapper mainly used to trace last activity timestamp.
// It's logic may involve in the future to fulfil audits and metrics collection requirements.
type traceable struct {
	Protector

	lastOpsAt time.Time
	opsMu     sync.RWMutex
}

var _ Protector = &traceable{}

func (tp *traceable) markOp() {
	tp.opsMu.Lock()
	defer tp.opsMu.Unlock()

	tp.lastOpsAt = time.Now()
}

// Decrypt implements Protector
func (tp *traceable) Decrypt(ctx context.Context, structPts ...interface{}) error {
	defer tp.markOp()
	return tp.Protector.Decrypt(ctx, structPts...)
}

// Encrypt implements Protector
func (tp *traceable) Encrypt(ctx context.Context, structPts ...interface{}) error {
	defer tp.markOp()
	return tp.Protector.Encrypt(ctx, structPts...)
}

// EncryptStream implements Protector
func (tp *traceable) EncryptStream(ctx context.Context, subID string, r io.Reader) (io.Reader, error) {
	defer tp.markOp()
	return tp.Protector.EncryptStream(ctx, subID, r)
}

// DecryptStream implements Protector
func (tp *traceable) DecryptStream(ctx context.Context, subID string, r io.Reader) (io.Reader, error) {
	defer tp.markOp()
	return tp.Protector.DecryptStream(ctx, subID, r)
}

// Forget implements Protector
func (tp *traceable) Forget(ctx context.Context, subID string) error {
	defer tp.markOp()
	return tp.Protector.Forget(ctx, subID)
}

// Recover implements Protector
func (tp *traceable) Recover(ctx context.Context, subID string) error {
	defer tp.markOp()
	return tp.Protector.Recover(ctx, subID)
}

// Clear implements Protector
// func (tp *traceable) Clear(ctx context.Context, force bool) error {
// 	return tp.Protector.Clear(ctx, force)
// }
