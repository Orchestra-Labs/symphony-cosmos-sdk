package types

import (
	"fmt"
	"math"
	"os"
	"runtime/trace"
	time "time"
)

// Gas consumption descriptors.
const (
	GasIterNextCostFlatDesc = "IterNextFlat"
	GasValuePerByteDesc     = "ValuePerByte"
	GasWritePerByteDesc     = "WritePerByte"
	GasReadPerByteDesc      = "ReadPerByte"
	GasWriteCostFlatDesc    = "WriteFlat"
	GasReadCostFlatDesc     = "ReadFlat"
	GasHasDesc              = "Has"
	GasDeleteDesc           = "Delete"

	filename = "/osmosis/node_trace.out"
)

// Gas measured by the SDK
type Gas = uint64

// ErrorNegativeGasConsumed defines an error thrown when the amount of gas refunded results in a
// negative gas consumed amount.
type ErrorNegativeGasConsumed struct {
	Descriptor string
}

// ErrorOutOfGas defines an error thrown when an action results in out of gas.
type ErrorOutOfGas struct {
	Descriptor string
}

// ErrorGasOverflow defines an error thrown when an action results gas consumption
// unsigned integer overflow.
type ErrorGasOverflow struct {
	Descriptor string
}

// GasMeter interface to track gas consumption
type GasMeter interface {
	GasConsumed() Gas
	GasConsumedToLimit() Gas
	GasRemaining() Gas
	Limit() Gas
	ConsumeGas(amount Gas, descriptor string)
	RefundGas(amount Gas, descriptor string)
	IsPastLimit() bool
	IsOutOfGas() bool
	String() string
}

type basicGasMeter struct {
	limit    Gas
	consumed Gas
}

// NewGasMeter returns a reference to a new basicGasMeter.
func NewGasMeter(limit Gas) GasMeter {
	return &basicGasMeter{
		limit:    limit,
		consumed: 0,
	}
}

// GasConsumed returns the gas consumed from the GasMeter.
func (g *basicGasMeter) GasConsumed() Gas {
	return g.consumed
}

// GasRemaining returns the gas left in the GasMeter.
func (g *basicGasMeter) GasRemaining() Gas {
	if g.IsPastLimit() {
		return 0
	}
	return g.limit - g.consumed
}

// Limit returns the gas limit of the GasMeter.
func (g *basicGasMeter) Limit() Gas {
	return g.limit
}

// GasConsumedToLimit returns the gas limit if gas consumed is past the limit,
// otherwise it returns the consumed gas.
//
// NOTE: This behavior is only called when recovering from panic when
// BlockGasMeter consumes gas past the limit.
func (g *basicGasMeter) GasConsumedToLimit() Gas {
	if g.IsPastLimit() {
		return g.limit
	}
	return g.consumed
}

// addUint64Overflow performs the addition operation on two uint64 integers and
// returns a boolean on whether or not the result overflows.
func addUint64Overflow(a, b uint64) (uint64, bool) {
	if math.MaxUint64-a < b {
		return 0, true
	}

	return a + b, false
}

// ConsumeGas adds the given amount of gas to the gas consumed and panics if it overflows the limit or out of gas.
func (g *basicGasMeter) ConsumeGas(amount Gas, descriptor string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		panic(err)
	}
	if err := trace.Start(file); err != nil {
		fmt.Println("Error starting trace:", err)
		panic(err)
	}
	defer func() {
		trace.Stop()
		file.Close()
	}()

	fmt.Printf("consume gas for %v of amount %v \n", descriptor, amount)
	fileName, err := createOrGetFileBasedOnTimestamp()
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}

	err = appendToFile(fileName, fmt.Sprintf("consume gas for %v of amount %v \n", descriptor, amount))
	if err != nil {
		fmt.Println("Error appending to file:", err)
		return
	}
	var overflow bool
	g.consumed, overflow = addUint64Overflow(g.consumed, amount)
	if overflow {
		g.consumed = math.MaxUint64
		panic(ErrorGasOverflow{descriptor})
	}

	if g.consumed > g.limit {
		panic(ErrorOutOfGas{descriptor})
	}
}

// RefundGas will deduct the given amount from the gas consumed. If the amount is greater than the
// gas consumed, the function will panic.
//
// Use case: This functionality enables refunding gas to the transaction or block gas pools so that
// EVM-compatible chains can fully support the go-ethereum StateDb interface.
// See https://github.com/cosmos/cosmos-sdk/pull/9403 for reference.
func (g *basicGasMeter) RefundGas(amount Gas, descriptor string) {
	if g.consumed < amount {
		panic(ErrorNegativeGasConsumed{Descriptor: descriptor})
	}

	g.consumed -= amount
}

// IsPastLimit returns true if gas consumed is past limit, otherwise it returns false.
func (g *basicGasMeter) IsPastLimit() bool {
	return g.consumed > g.limit
}

// IsOutOfGas returns true if gas consumed is greater than or equal to gas limit, otherwise it returns false.
func (g *basicGasMeter) IsOutOfGas() bool {
	return g.consumed >= g.limit
}

// String returns the BasicGasMeter's gas limit and gas consumed.
func (g *basicGasMeter) String() string {
	return fmt.Sprintf("BasicGasMeter:\n  limit: %d\n  consumed: %d", g.limit, g.consumed)
}

type infiniteGasMeter struct {
	consumed Gas
}

// NewInfiniteGasMeter returns a new gas meter without a limit.
func NewInfiniteGasMeter() GasMeter {
	return &infiniteGasMeter{
		consumed: 0,
	}
}

// GasConsumed returns the gas consumed from the GasMeter.
func (g *infiniteGasMeter) GasConsumed() Gas {
	return g.consumed
}

// GasConsumedToLimit returns the gas consumed from the GasMeter since the gas is not confined to a limit.
// NOTE: This behaviour is only called when recovering from panic when BlockGasMeter consumes gas past the limit.
func (g *infiniteGasMeter) GasConsumedToLimit() Gas {
	return g.consumed
}

// GasRemaining returns MaxUint64 since limit is not confined in infiniteGasMeter.
func (g *infiniteGasMeter) GasRemaining() Gas {
	return math.MaxUint64
}

// Limit returns MaxUint64 since limit is not confined in infiniteGasMeter.
func (g *infiniteGasMeter) Limit() Gas {
	return math.MaxUint64
}

// ConsumeGas adds the given amount of gas to the gas consumed and panics if it overflows the limit.
func (g *infiniteGasMeter) ConsumeGas(amount Gas, descriptor string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		panic(err)
	}
	if err := trace.Start(file); err != nil {
		fmt.Println("Error starting trace:", err)
		panic(err)
	}
	defer func() {
		trace.Stop()
		file.Close()
	}()

	var overflow bool
	fmt.Printf("infinite gas meter consume gas for %v of amount %v \n", descriptor, amount)
	fileName, err := createOrGetFileBasedOnTimestamp()
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}

	err = appendToFile(fileName, fmt.Sprintf("infinite gas meter consume gas for %v of amount %v \n", descriptor, amount))
	if err != nil {
		fmt.Println("Error appending to file:", err)
		return
	}
	// TODO: Should we set the consumed field after overflow checking?
	g.consumed, overflow = addUint64Overflow(g.consumed, amount)
	if overflow {
		panic(ErrorGasOverflow{descriptor})
	}
}

// RefundGas will deduct the given amount from the gas consumed. If the amount is greater than the
// gas consumed, the function will panic.
//
// Use case: This functionality enables refunding gas to the trasaction or block gas pools so that
// EVM-compatible chains can fully support the go-ethereum StateDb interface.
// See https://github.com/cosmos/cosmos-sdk/pull/9403 for reference.
func (g *infiniteGasMeter) RefundGas(amount Gas, descriptor string) {
	if g.consumed < amount {
		panic(ErrorNegativeGasConsumed{Descriptor: descriptor})
	}

	g.consumed -= amount
}

// IsPastLimit returns false since the gas limit is not confined.
func (g *infiniteGasMeter) IsPastLimit() bool {
	return false
}

// IsOutOfGas returns false since the gas limit is not confined.
func (g *infiniteGasMeter) IsOutOfGas() bool {
	return false
}

// String returns the InfiniteGasMeter's gas consumed.
func (g *infiniteGasMeter) String() string {
	return fmt.Sprintf("InfiniteGasMeter:\n  consumed: %d", g.consumed)
}

// GasConfig defines gas cost for each operation on KVStores
type GasConfig struct {
	HasCost          Gas
	DeleteCost       Gas
	ReadCostFlat     Gas
	ReadCostPerByte  Gas
	WriteCostFlat    Gas
	WriteCostPerByte Gas
	IterNextCostFlat Gas
}

// KVGasConfig returns a default gas config for KVStores.
func KVGasConfig() GasConfig {
	return GasConfig{
		HasCost:          1000,
		DeleteCost:       1000,
		ReadCostFlat:     1000,
		ReadCostPerByte:  3,
		WriteCostFlat:    2000,
		WriteCostPerByte: 30,
		IterNextCostFlat: 30,
	}
}

// TransientGasConfig returns a default gas config for TransientStores.
func TransientGasConfig() GasConfig {
	return GasConfig{
		HasCost:          100,
		DeleteCost:       100,
		ReadCostFlat:     100,
		ReadCostPerByte:  0,
		WriteCostFlat:    200,
		WriteCostPerByte: 3,
		IterNextCostFlat: 3,
	}
}

// Creates a new file with a name based on the current timestamp rounded to 5 seconds
func createOrGetFileBasedOnTimestamp() (string, error) {
	now := time.Now()
	// Round down to the nearest 5 seconds
	roundedTime := now.Truncate(5 * time.Second)

	// Check for files in the last 5 seconds
	for i := 0; i < 5; i++ {
		fileName := fmt.Sprintf("file_%d.txt", roundedTime.Unix()-int64(i))
		if _, err := os.Stat(fileName); err == nil {
			return fileName, nil
		}
	}

	// If no file found, create a new one
	fileName := fmt.Sprintf("file_%d.txt", roundedTime.Unix())
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return fileName, nil
}

// Appends data to the specified file
func appendToFile(fileName string, data string) error {
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(data)
	return err
}
