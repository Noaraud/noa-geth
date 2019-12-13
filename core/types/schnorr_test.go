package types

import (
	//"fmt"
	"testing"
	"encoding/hex"
	"math/big"
	"github.com/btcsuite/btcd/btcec"
	"github.com/Noaraud/noa-geth/common"
	"github.com/Noaraud/noa-geth/crypto"
)

func TestVerify(t *testing.T) {
	var (
		message   [32]byte
		signature [64]byte
	)
	  
	pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	
	msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	copy(message[:], msg)
	sig, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
	copy(signature[:], sig)
	  
	result, err := Verify(pk, message, signature)
	if result == nil {
		t.Fatal(err)
	}
	t.Log(result)


	//t.Log(len(result))
	//t.Log(hex.EncodeToString(result[:32]))
	//pubstring := "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
	//t.Log(pubstring)
	//if hex.EncodeToString(result[:32]) != pubstring {
	//	t.Log("invalid")
	//}



	var addr common.Address
	copy(addr[:], crypto.Keccak256(result[:])[12:])
	//t.Log(addr)
	//t.Log(hex.EncodeToString(crypto.Keccak256(result[:])[12:]))
	
}


func TestUnmarshal(t *testing.T) {
	var publicKey [33]byte
	var curve = btcec.S256()
	byteLen := (curve.Params().BitSize + 7) >> 3
	
	pk, _ := hex.DecodeString("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	copy(publicKey[:], pk)


	pubkeyX, _ := hex.DecodeString("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	should := new(big.Int).SetBytes(pubkeyX)
	t.Log(should)

	x0 := new(big.Int).SetBytes(publicKey[0:byteLen])
	t.Log(x0)
	t.Log(byteLen)

	if x0 != should {
		t.Error("exected pubkey to be equal.\n Got", x0, "\nwant", should)
	}
}

func TestHoge(t *testing.T) {
	pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
	pk2, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA888")

	t.Log(pk)
	t.Log(pk2)

	var Pubkey [64]byte

	copy(Pubkey[:32], pk)
	copy(Pubkey[32:], pk2)
	var PubkeySlice []byte

	PubkeySlice = Pubkey[:]
	t.Log(PubkeySlice)
}