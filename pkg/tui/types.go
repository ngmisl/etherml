package tui

import (
	"time"
	
	"wallet/pkg/quantum"
)

// Type aliases for consistent usage across TUI package
type (
	PrivateKey    = quantum.PrivateKey
	PublicKey     = quantum.PublicKey
	Address       = quantum.Address
	Salt          = quantum.Salt
	Nonce         = quantum.Nonce
	EncryptedData = quantum.EncryptedData
	KDFParams     = quantum.KDFParams
)

// Wallet represents an Ethereum wallet (TUI view model)
type Wallet struct {
	PrivateKey PrivateKey `json:"-"`
	Address    Address    `json:"address"`
	CreatedAt  time.Time  `json:"created_at"`
	Label      string     `json:"label,omitempty"`
}

// WalletManagerInterface defines the interface that the TUI needs from the wallet manager
type WalletManagerInterface interface {
	ListWallets() ([]Wallet, error)
	AddWallet(*Wallet) error
	DeleteWallet(string) error
	UpdateWalletLabel(address string, newLabel string) error
	Save() error
}

// SecureData interface for sensitive operations
type SecureData interface {
	Zero()
}

// Result type for error handling
type Result[T any] struct {
	value T
	err   error
}

func Ok[T any](value T) Result[T] {
	return Result[T]{value: value}
}

func Err[T any](err error) Result[T] {
	return Result[T]{err: err}
}

func (r Result[T]) Unwrap() (T, error) {
	return r.value, r.err
}

// Option type for nullable values
type Option[T any] struct {
	value *T
}

func Some[T any](value T) Option[T] {
	return Option[T]{value: &value}
}

func None[T any]() Option[T] {
	return Option[T]{value: nil}
}

func (o Option[T]) IsSome() bool {
	return o.value != nil
}

func (o Option[T]) Unwrap() T {
	if o.value == nil {
		panic("unwrap on None")
	}
	return *o.value
}