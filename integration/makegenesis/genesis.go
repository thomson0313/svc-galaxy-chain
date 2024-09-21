package makegenesis

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/galaxy-digital/lachesis-base/hash"
	"github.com/galaxy-digital/lachesis-base/inter/idx"

	galaxy "github.com/galaxy-digital/galaxychain-chain/galaxy"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesis"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesis/driver"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesis/driverauth"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesis/evmwriter"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesis/gpos"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesis/netinit"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesis/sfc"
	"github.com/galaxy-digital/galaxychain-chain/galaxy/genesisstore"
	"github.com/galaxy-digital/galaxychain-chain/inter"
	"github.com/galaxy-digital/galaxychain-chain/inter/validatorpk"
	futils "github.com/galaxy-digital/galaxychain-chain/utils"
)

var (
	FakeGenesisTime = inter.Timestamp(1608600000 * time.Second)
)

// FakeKey gets n-th fake private key.
func FakeKey(n int) *ecdsa.PrivateKey {
	reader := rand.New(rand.NewSource(int64(n)))

	key, err := ecdsa.GenerateKey(crypto.S256(), reader)

	fmt.Printf("\nYour new privatekey was generated %x\n", key.D)

	if err != nil {
		panic(err)
	}

	return key
}

type ValidatorAccount struct {
	address   string
	validator string
}

func MakeGenesisStore() *genesisstore.Store {
	genStore := genesisstore.NewMemStore()
	genStore.SetRules(galaxy.MainNetRules())

	var validatorAccounts = []ValidatorAccount{
		// for mainnet
		{
			address:   "0xf3A7d240016E7c749896B84646E175EaEa853108",
			validator: "04c95aec5b64959a33c1c650f76ca34a84a56cea7d51f46db13c7039abb239821bbd979b31e5d6e643ce04ebe7cbb72a96f465586a7e682fb9d742624d2acef022",
		},
		{
			address:   "0x4305C1a4558547b4e5Be5bfDc06F18336ce9ebEa",
			validator: "04ecbe6f8b889ac4502a46078a595b124e1fb543e2cc84dc4036ed547d7de5bba6e3559ef70539611974194482bc614c08f8340bb77d5b144905b94156663bbbd6",
		},
		{
			address:   "0xc1aB8d7F73e71324459fD43Cf08dDEd22122dbdB",
			validator: "045c2290dea6248964a6846fd192f5932ffa7189cb2140855577c6d71a7f96c11e76cdb4fd7dec12ee530c26a4d0f45c934aa013828aed288936c0fb8332cda805",
		},
	}

	var initialAccounts = []string{
		"0x7b1A3b9A4Ee32E6A8688A93188ed5E2c146Eb013",
	}
	num := len(validatorAccounts)

	_total := int(4e8)
	_validator := 0
	_staker := int(1e6)
	_initial := (_total - (_validator+_staker)*num) / len(initialAccounts)

	totalSupply := futils.ToGlxy(uint64(_total))
	balance := futils.ToGlxy(uint64(_validator))
	stake := futils.ToGlxy(uint64(_staker))
	initialBalance := futils.ToGlxy(uint64(_initial))

	validators := make(gpos.Validators, 0, num)

	now := time.Now() // current local time
	// sec := now.Unix()      // number of seconds since January 1, 1970 UTC
	nsec := now.UnixNano()
	time := inter.Timestamp(nsec)
	for i := 1; i <= num; i++ {
		addr := common.HexToAddress(validatorAccounts[i-1].address)
		pubkeyraw := common.Hex2Bytes(validatorAccounts[i-1].validator)
		// fmt.Printf("\n# addr %x pubkeyraw %s len %d\n", addr, hex.EncodeToString(pubkeyraw), len(pubkeyraw))
		validatorID := idx.ValidatorID(i)
		pubKey := validatorpk.PubKey{
			Raw:  pubkeyraw,
			Type: validatorpk.Types.Secp256k1,
		}

		validators = append(validators, gpos.Validator{
			ID:               validatorID,
			Address:          addr,
			PubKey:           pubKey,
			CreationTime:     time,
			CreationEpoch:    0,
			DeactivatedTime:  0,
			DeactivatedEpoch: 0,
			Status:           0,
		})
	}
	for _, val := range initialAccounts {
		genStore.SetEvmAccount(common.HexToAddress(val), genesis.Account{
			Code:    []byte{},
			Balance: initialBalance,
			Nonce:   0,
		})
	}
	for _, val := range validators {
		genStore.SetEvmAccount(val.Address, genesis.Account{
			Code:    []byte{},
			Balance: balance,
			Nonce:   0,
		})
		genStore.SetDelegation(val.Address, val.ID, genesis.Delegation{
			Stake:              stake,
			Rewards:            new(big.Int),
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
		})
	}

	var owner common.Address
	if num != 0 {
		owner = validators[0].Address
	}

	genStore.SetMetadata(genesisstore.Metadata{
		Validators:    validators,
		FirstEpoch:    2,
		Time:          time,
		PrevEpochTime: time - inter.Timestamp(time.Time().Hour()),
		ExtraData:     []byte("galaxy"),
		DriverOwner:   owner,
		TotalSupply:   totalSupply,
	})
	genStore.SetBlock(0, genesis.Block{
		Time:        time - inter.Timestamp(time.Time().Minute()),
		Atropos:     hash.Event{},
		Txs:         types.Transactions{},
		InternalTxs: types.Transactions{},
		Root:        hash.Hash{},
		Receipts:    []*types.ReceiptForStorage{},
	})
	// pre deploy NetworkInitializer
	genStore.SetEvmAccount(netinit.ContractAddress, genesis.Account{
		Code:    netinit.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriver
	genStore.SetEvmAccount(driver.ContractAddress, genesis.Account{
		Code:    driver.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriverAuth
	genStore.SetEvmAccount(driverauth.ContractAddress, genesis.Account{
		Code:    driverauth.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy SFC
	genStore.SetEvmAccount(sfc.ContractAddress, genesis.Account{
		Code:    sfc.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// set non-zero code for pre-compiled contracts
	genStore.SetEvmAccount(evmwriter.ContractAddress, genesis.Account{
		Code:    []byte{0},
		Balance: new(big.Int),
		Nonce:   0,
	})

	return genStore
}

func MakeTestnetGenesisStore() *genesisstore.Store {
	genStore := genesisstore.NewMemStore()
	genStore.SetRules(galaxy.TestNetRules())
	var validatorAccounts = []ValidatorAccount{
		{
			address:   "0xB16C96e999E223C194e3Dde1D545b3d7432Ae990",
			validator: "045fef2cf62624de0235e014a0e98b0f0983412394d491445583479bb2f28a14e8210f8a8b5c6e438ab8202f3daef81078120cd2c2346f557c8e4c3151bdaf44d7",
		},
		{
			address:   "0x1b5FDcB4f2045baa47622D95625a8c5032D9cF09",
			validator: "04e6f3c7e116e0ff15ce91571ec2af4bd10cdbccef8d71ec04f8cb12c9d8a07ff571960889363acd97cf582f5d51677f61a00f8975c5f6a48072366877351ee69e",
		},
		{
			address:   "0x7147B98A74e8CcC72F266600AD127Da389ec0E98",
			validator: "04e299ca1c2dec031fe4bc46004ee6ecafe5cedf7e392c95bf64a2de63757773f36fb2a632494c69b21b2cd86dc331c6298a4a7d1019b89aa680368366c8af8d8f",
		},
		{
			address:   "0x95f82957c87A4c2827759C13335f691acEb0b229",
			validator: "042520b24f3cb51c56cb5283e335c5cf1aa49bc61b8beb8c2919565c4f86928057563c183f1744704e585e4b74f15ac7e3e8ef4b1fcc2828a81fdb4a6cf603330b",
		},
	}
	var initialAccounts = []string{
		"0xFad6ed03f8aA1C8841C49C7ae34107d46F5f010a",
	}

	num := len(validatorAccounts)

	_total := int(1e6)
	_validator := 0
	_staker := int(1 * 1e4)
	_initial := (_total - (_validator+_staker)*num) / len(initialAccounts)

	totalSupply := futils.ToGlxy(uint64(_total))
	balance := futils.ToGlxy(uint64(_validator))
	stake := futils.ToGlxy(uint64(_staker))
	initialBalance := futils.ToGlxy(uint64(_initial))

	validators := make(gpos.Validators, 0, num)

	now := time.Now() // current local time
	// sec := now.Unix()      // number of seconds since January 1, 1970 UTC
	nsec := now.UnixNano()
	time := inter.Timestamp(nsec)
	for i := 1; i <= num; i++ {
		addr := common.HexToAddress(validatorAccounts[i-1].address)
		pubkeyraw := common.Hex2Bytes(validatorAccounts[i-1].validator)
		fmt.Printf("\n# addr %x pubkeyraw %s len %d\n", addr, hex.EncodeToString(pubkeyraw), len(pubkeyraw))
		validatorID := idx.ValidatorID(i)
		pubKey := validatorpk.PubKey{
			Raw:  pubkeyraw,
			Type: validatorpk.Types.Secp256k1,
		}

		validators = append(validators, gpos.Validator{
			ID:               validatorID,
			Address:          addr,
			PubKey:           pubKey,
			CreationTime:     time,
			CreationEpoch:    0,
			DeactivatedTime:  0,
			DeactivatedEpoch: 0,
			Status:           0,
		})
	}

	for _, val := range initialAccounts {
		genStore.SetEvmAccount(common.HexToAddress(val), genesis.Account{
			Code:    []byte{},
			Balance: initialBalance,
			Nonce:   0,
		})
	}

	for _, val := range validators {
		genStore.SetEvmAccount(val.Address, genesis.Account{
			Code:    []byte{},
			Balance: balance,
			Nonce:   0,
		})
		genStore.SetDelegation(val.Address, val.ID, genesis.Delegation{
			Stake:              stake,
			Rewards:            new(big.Int),
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
		})
	}

	var owner common.Address
	if num != 0 {
		owner = validators[0].Address
	}

	genStore.SetMetadata(genesisstore.Metadata{
		Validators:    validators,
		FirstEpoch:    2,
		Time:          time,
		PrevEpochTime: time - inter.Timestamp(time.Time().Hour()),
		ExtraData:     []byte("fake"),
		DriverOwner:   owner,
		TotalSupply:   totalSupply,
	})
	genStore.SetBlock(0, genesis.Block{
		Time:        time - inter.Timestamp(time.Time().Minute()),
		Atropos:     hash.Event{},
		Txs:         types.Transactions{},
		InternalTxs: types.Transactions{},
		Root:        hash.Hash{},
		Receipts:    []*types.ReceiptForStorage{},
	})
	// pre deploy NetworkInitializer
	genStore.SetEvmAccount(netinit.ContractAddress, genesis.Account{
		Code:    netinit.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriver
	genStore.SetEvmAccount(driver.ContractAddress, genesis.Account{
		Code:    driver.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriverAuth
	genStore.SetEvmAccount(driverauth.ContractAddress, genesis.Account{
		Code:    driverauth.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy SFC
	genStore.SetEvmAccount(sfc.ContractAddress, genesis.Account{
		Code:    sfc.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// set non-zero code for pre-compiled contracts
	genStore.SetEvmAccount(evmwriter.ContractAddress, genesis.Account{
		Code:    []byte{0},
		Balance: new(big.Int),
		Nonce:   0,
	})

	return genStore
}
func FakeGenesisStore(num int, balance, stake *big.Int) *genesisstore.Store {
	genStore := genesisstore.NewMemStore()
	genStore.SetRules(galaxy.FakeNetRules())

	validators := GetFakeValidators(num)

	totalSupply := new(big.Int)
	for _, val := range validators {
		genStore.SetEvmAccount(val.Address, genesis.Account{
			Code:    []byte{},
			Balance: balance,
			Nonce:   0,
		})
		genStore.SetDelegation(val.Address, val.ID, genesis.Delegation{
			Stake:              stake,
			Rewards:            new(big.Int),
			LockedStake:        new(big.Int),
			LockupFromEpoch:    0,
			LockupEndTime:      0,
			LockupDuration:     0,
			EarlyUnlockPenalty: new(big.Int),
		})
		totalSupply.Add(totalSupply, balance)
	}

	var owner common.Address
	if num != 0 {
		owner = validators[0].Address
	}

	genStore.SetMetadata(genesisstore.Metadata{
		Validators:    validators,
		FirstEpoch:    2,
		Time:          FakeGenesisTime,
		PrevEpochTime: FakeGenesisTime - inter.Timestamp(time.Hour),
		ExtraData:     []byte("fake"),
		DriverOwner:   owner,
		TotalSupply:   totalSupply,
	})
	genStore.SetBlock(0, genesis.Block{
		Time:        FakeGenesisTime - inter.Timestamp(time.Minute),
		Atropos:     hash.Event{},
		Txs:         types.Transactions{},
		InternalTxs: types.Transactions{},
		Root:        hash.Hash{},
		Receipts:    []*types.ReceiptForStorage{},
	})
	// pre deploy NetworkInitializer
	genStore.SetEvmAccount(netinit.ContractAddress, genesis.Account{
		Code:    netinit.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriver
	genStore.SetEvmAccount(driver.ContractAddress, genesis.Account{
		Code:    driver.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy NodeDriverAuth
	genStore.SetEvmAccount(driverauth.ContractAddress, genesis.Account{
		Code:    driverauth.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// pre deploy SFC
	genStore.SetEvmAccount(sfc.ContractAddress, genesis.Account{
		Code:    sfc.GetContractBin(),
		Balance: new(big.Int),
		Nonce:   0,
	})
	// set non-zero code for pre-compiled contracts
	genStore.SetEvmAccount(evmwriter.ContractAddress, genesis.Account{
		Code:    []byte{0},
		Balance: new(big.Int),
		Nonce:   0,
	})

	return genStore
}

func GetFakeValidators(num int) gpos.Validators {
	validators := make(gpos.Validators, 0, num)

	for i := 1; i <= num; i++ {
		key := FakeKey(i)
		addr := crypto.PubkeyToAddress(key.PublicKey)
		pubkeyraw := crypto.FromECDSAPub(&key.PublicKey)

		validatorID := idx.ValidatorID(i)
		validators = append(validators, gpos.Validator{
			ID:      validatorID,
			Address: addr,
			PubKey: validatorpk.PubKey{
				Raw:  pubkeyraw,
				Type: validatorpk.Types.Secp256k1,
			},
			CreationTime:     FakeGenesisTime,
			CreationEpoch:    0,
			DeactivatedTime:  0,
			DeactivatedEpoch: 0,
			Status:           0,
		})
	}

	return validators
}

type Genesis struct {
	Nonce      uint64         `json:"nonce"`
	Timestamp  uint64         `json:"timestamp"`
	ExtraData  []byte         `json:"extraData"`
	GasLimit   uint64         `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int       `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash    `json:"mixHash"`
	Coinbase   common.Address `json:"coinbase"`
	Alloc      GenesisAlloc   `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
	BaseFee    *big.Int    `json:"baseFeePerGas"`
}

type GenesisAlloc map[common.Address]GenesisAccount

type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}
