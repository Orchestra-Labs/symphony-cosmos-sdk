package debug

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/version"
)

var (
	flagPubkeyType = "type"
)

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Tool for helping with debugging your application",
		RunE:  client.ValidateCmd,
	}

	cmd.AddCommand(PubkeyCmd())
	cmd.AddCommand(AddrCmd())
	cmd.AddCommand(RawBytesCmd())

	return cmd
}

func bytesToPubkey(bz []byte, keytype string) (cryptotypes.PubKey, bool) {
	if keytype == "ed25519" { //nolint:goconst
		if len(bz) == ed25519.PubKeySize {
			return &ed25519.PubKey{Key: bz}, true
		}
	}

	if len(bz) == secp256k1.PubKeySize {
		return &secp256k1.PubKey{Key: bz}, true
	}
	return nil, false
}

// getPubKeyFromString returns a PubKey (PubKeyEd25519 or PubKeySecp256k1) by attempting
// to decode the pubkey string from hex, base64, and finally bech32. If all
// encodings fail, an error is returned.
func getPubKeyFromString(pkstr string, keytype string) (cryptotypes.PubKey, error) {
	// Try hex decoding
	bz, err := hex.DecodeString(pkstr)
	if err == nil {
		pk, ok := bytesToPubkey(bz, keytype)
		if ok {
			return pk, nil
		}
	}

	bz, err = base64.StdEncoding.DecodeString(pkstr)
	if err == nil {
		pk, ok := bytesToPubkey(bz, keytype)
		if ok {
			return pk, nil
		}
	}

	pk, err := sdk.GetPubKeyFromBech32(sdk.Bech32PubKeyTypeAccPub, pkstr)
	if err == nil {
		return pk, nil
	}

	pk, err = sdk.GetPubKeyFromBech32(sdk.Bech32PubKeyTypeValPub, pkstr)
	if err == nil {
		return pk, nil
	}

	pk, err = sdk.GetPubKeyFromBech32(sdk.Bech32PubKeyTypeConsPub, pkstr)
	if err == nil {
		return pk, nil
	}

	return nil, fmt.Errorf("pubkey '%s' invalid; expected hex, base64, or bech32 of correct size", pkstr)
}

func PubkeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pubkey [pubkey] -t [{ed25519, secp256k1}]",
		Short: "Decode a ED25519 or secp256k1 pubkey from hex, base64, or bech32",
		Long: fmt.Sprintf(`Decode a pubkey from hex, base64, or bech32.

Example:
$ %s debug pubkey TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz
$ %s debug pubkey cosmos1e0jnq2sun3dzjh8p2xq95kk0expwmd7shwjpfg
			`, version.AppName, version.AppName),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)

			pubkeyType, err := cmd.Flags().GetString(flagPubkeyType)
			if err != nil {
				return err
			}
			pubkeyType = strings.ToLower(pubkeyType)
			if pubkeyType != "secp256k1" && pubkeyType != "ed25519" { //nolint:goconst
				return errors.Wrapf(errors.ErrInvalidType, "invalid pubkey type, expected oneof ed25519 or secp256k1")
			}

			pk, err := getPubKeyFromString(args[0], pubkeyType)
			if err != nil {
				return err
			}

			var consensusPub string
			edPK, ok := pk.(*ed25519.PubKey)
			if ok && pubkeyType == "ed25519" {
				consensusPub, err = sdk.Bech32ifyPubKey(sdk.Bech32PubKeyTypeConsPub, edPK)
				if err != nil {
					return err
				}

				cmd.Printf("Hex: %X\n", edPK.Key)
			}
			cmd.Println("Parsed key as", pk.Type())

			pubKeyJSONBytes, err := clientCtx.LegacyAmino.MarshalJSON(pk)
			if err != nil {
				return err
			}
			accPub, err := sdk.Bech32ifyPubKey(sdk.Bech32PubKeyTypeAccPub, pk)
			if err != nil {
				return err
			}
			valPub, err := sdk.Bech32ifyPubKey(sdk.Bech32PubKeyTypeValPub, pk)
			if err != nil {
				return err
			}
			cmd.Println("Address:", pk.Address())
			cmd.Println("JSON (base64):", string(pubKeyJSONBytes))
			cmd.Println("Bech32 Acc:", accPub)
			cmd.Println("Bech32 Validator Operator:", valPub)
			if pubkeyType == "ed25519" {

				cmd.Println("Bech32 Validator Consensus:", consensusPub)
			}

			return nil
		},
	}
	cmd.Flags().StringP(flagPubkeyType, "t", "ed25519", "Pubkey type to decode (oneof secp256k1, ed25519)")
	return cmd
}

func AddrCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "addr [address]",
		Short: "Convert an address between hex and bech32",
		Long: fmt.Sprintf(`Convert an address between hex encoding and bech32.
			
Example:
$ %s debug addr cosmos1e0jnq2sun3dzjh8p2xq95kk0expwmd7shwjpfg
			`, version.AppName),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			addrString := args[0]
			var addr []byte

			// try hex, then bech32
			var err error
			addr, err = hex.DecodeString(addrString)
			if err != nil {
				var err2 error
				addr, err2 = sdk.AccAddressFromBech32(addrString)
				if err2 != nil {
					var err3 error
					addr, err3 = sdk.ValAddressFromBech32(addrString)

					if err3 != nil {
						return fmt.Errorf("expected hex or bech32. Got errors: hex: %v, bech32 acc: %v, bech32 val: %v", err, err2, err3)

					}
				}
			}

			accAddr := sdk.AccAddress(addr)
			valAddr := sdk.ValAddress(addr)

			cmd.Println("Address:", addr)
			cmd.Printf("Address (hex): %X\n", addr)
			cmd.Printf("Bech32 Acc: %s\n", accAddr)
			cmd.Printf("Bech32 Val: %s\n", valAddr)
			return nil
		},
	}
}

func RawBytesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "raw-bytes [raw-bytes]",
		Short: "Convert raw bytes output (eg. [10 21 13 255]) to hex",
		Long: fmt.Sprintf(`Convert raw-bytes to hex.
			
Example:
$ %s debug raw-bytes [72 101 108 108 111 44 32 112 108 97 121 103 114 111 117 110 100]
			`, version.AppName),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			stringBytes := args[0]
			stringBytes = strings.Trim(stringBytes, "[")
			stringBytes = strings.Trim(stringBytes, "]")
			spl := strings.Split(stringBytes, " ")

			byteArray := []byte{}
			for _, s := range spl {
				b, err := strconv.ParseInt(s, 10, 8)
				if err != nil {
					return err
				}
				byteArray = append(byteArray, byte(b))
			}
			fmt.Printf("%X\n", byteArray)
			return nil
		},
	}
}
