package types

import (
	"encoding/hex"
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

var (
	_ sdk.AccountI                       = (*EthAccount)(nil)
	_ GenesisAccount                     = (*EthAccount)(nil)
	_ codectypes.UnpackInterfacesMessage = (*EthAccount)(nil)
)

// EmptyCodeHash is the keccak256 hash of empty bytes — the code hash assigned
// to externally-owned accounts (EOAs) that have no contract code.
// Value: keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
const EmptyCodeHash = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

// EthAccount is an account type for EVM-compatible addresses on Symphony.
// It embeds BaseAccount and adds a CodeHash field used by the EVM module to
// identify contract accounts (non-empty code hash) vs EOAs (empty code hash).
//
// The account address is a standard 20-byte Cosmos AccAddress derived from an
// eth_secp256k1 public key, making it identical to the Ethereum address. The
// bech32 representation uses the Symphony account prefix ("symphony1...").
type EthAccount struct {
	*BaseAccount `protobuf:"bytes,1,opt,name=base_account,json=baseAccount,proto3,embedded=base_account" json:"base_account,omitempty"`
	// CodeHash is the keccak256 hash of the EVM contract bytecode for this
	// account. Empty for EOAs (value: EmptyCodeHash).
	CodeHash string `protobuf:"bytes,2,opt,name=code_hash,json=codeHash,proto3" json:"code_hash,omitempty"`
}

// NewEthAccount creates a new EthAccount from a BaseAccount.
// CodeHash is initialized to EmptyCodeHash (externally-owned account).
func NewEthAccount(baseAcc *BaseAccount) *EthAccount {
	return &EthAccount{
		BaseAccount: baseAcc,
		CodeHash:    EmptyCodeHash,
	}
}

// NewEthAccountWithCode creates a new EthAccount with a specific code hash.
// Used when creating contract accounts during EVM execution.
func NewEthAccountWithCode(baseAcc *BaseAccount, codeHash []byte) *EthAccount {
	return &EthAccount{
		BaseAccount: baseAcc,
		CodeHash:    hex.EncodeToString(codeHash),
	}
}

// EthAddress returns the underlying 20-byte Ethereum address as a hex string
// (without "0x" prefix). This is the canonical EVM address for this account.
func (acc EthAccount) EthAddress() string {
	addr := acc.GetAddress()
	if len(addr) != 20 {
		return ""
	}
	return hex.EncodeToString(addr)
}

// GetCodeHash returns the account's code hash as a byte slice.
// Returns nil if the code hash string is invalid or empty.
func (acc EthAccount) GetCodeHash() []byte {
	if acc.CodeHash == "" {
		return nil
	}
	bz, err := hex.DecodeString(acc.CodeHash)
	if err != nil {
		return nil
	}
	return bz
}

// IsContract returns true when the account has non-empty EVM contract code.
func (acc EthAccount) IsContract() bool {
	return acc.CodeHash != "" && acc.CodeHash != EmptyCodeHash
}

// Validate checks the account fields for consistency.
func (acc EthAccount) Validate() error {
	if acc.BaseAccount == nil {
		return fmt.Errorf("EthAccount: BaseAccount is nil")
	}
	if err := acc.BaseAccount.Validate(); err != nil {
		return err
	}
	// Validate that the address is exactly 20 bytes (Ethereum address length).
	addr := acc.GetAddress()
	if len(addr) != 20 {
		return fmt.Errorf("EthAccount: address must be 20 bytes, got %d", len(addr))
	}
	// Validate code hash format (must be valid hex, 32 bytes = 64 hex chars).
	if acc.CodeHash != "" {
		bz, err := hex.DecodeString(acc.CodeHash)
		if err != nil {
			return fmt.Errorf("EthAccount: invalid code hash hex: %w", err)
		}
		if len(bz) != 32 {
			return fmt.Errorf("EthAccount: code hash must be 32 bytes, got %d", len(bz))
		}
	}
	return nil
}

// SetPubKey sets the public key on the embedded BaseAccount.
// Only eth_secp256k1 public keys are compatible with EthAccount addresses.
func (acc *EthAccount) SetPubKey(pubKey cryptotypes.PubKey) error {
	return acc.BaseAccount.SetPubKey(pubKey)
}

// UnpackInterfaces implements UnpackInterfacesMessage.
func (acc EthAccount) UnpackInterfaces(unpacker codectypes.AnyUnpacker) error {
	if acc.BaseAccount != nil {
		return acc.BaseAccount.UnpackInterfaces(unpacker)
	}
	return nil
}

// Type returns the account type string, used in CLI output.
func (acc EthAccount) Type() string { return "EthAccount" }

// ProtoEthAccount is a prototype function for use with the account keeper.
func ProtoEthAccount() sdk.AccountI {
	return &EthAccount{BaseAccount: &BaseAccount{}}
}

// String implements the fmt.Stringer interface.
func (acc EthAccount) String() string {
	return fmt.Sprintf("EthAccount{Address: %s, CodeHash: %s}", acc.GetAddress(), acc.CodeHash)
}

// Reset implements proto.Message.
func (acc *EthAccount) Reset() { *acc = EthAccount{} }

// ProtoMessage implements proto.Message.
func (*EthAccount) ProtoMessage() {}

// ---- Manual proto Marshal / Unmarshal ----
// EthAccount is serialised as: field1=BaseAccount (embedded), field2=CodeHash string

func (m *EthAccount) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *EthAccount) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *EthAccount) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i

	// Field 2: CodeHash (string)
	if len(m.CodeHash) > 0 {
		i -= len(m.CodeHash)
		copy(dAtA[i:], m.CodeHash)
		i = encodeVarintEthAccount(dAtA, i, uint64(len(m.CodeHash)))
		i--
		dAtA[i] = 0x12 // field 2, wire type 2
	}

	// Field 1: BaseAccount (embedded message)
	if m.BaseAccount != nil {
		n, err := m.BaseAccount.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= n
		i = encodeVarintEthAccount(dAtA, i, uint64(n))
		i--
		dAtA[i] = 0xa // field 1, wire type 2
	}

	return len(dAtA) - i, nil
}

func (m *EthAccount) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l

	if m.BaseAccount != nil {
		l = m.BaseAccount.Size()
		n += 1 + l + sovEthAccount(uint64(l))
	}

	l = len(m.CodeHash)
	if l > 0 {
		n += 1 + l + sovEthAccount(uint64(l))
	}

	return n
}

func encodeVarintEthAccount(dAtA []byte, offset int, v uint64) int {
	offset -= sovEthAccount(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}

func sovEthAccount(x uint64) (n int) {
	// equivalent to (bits.Len64(x|1) + 6) / 7
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
