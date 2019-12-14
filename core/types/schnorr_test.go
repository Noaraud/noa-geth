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
	var (
		message   [32]byte
		signature [64]byte
	)
	  
	pk, _ := hex.DecodeString("023a968c4c1a6127102fe60e2706476b23d8f6c3e147937a7252a5c35f61f0938e")
	
	//msg, _ := hex.DecodeString("4886c43cb65240e968051b4b525ee06ccbea41a7c7304fcef9326da36e78564f")
	msg, _ := hex.DecodeString("db7e80e96b8bf43e438ad3c0845658909ca84fe60c06bb3704c70e8cf6a1706c")
	copy(message[:], msg)
	//sig, _ := hex.DecodeString("aacaace16017dfc44427266dec0bb71d73118d7f31e24ab70b6a88a3d6c635383bebe3ecaa0dec230133331e66d421ffe06c239276d0490888da9496e02284f0")
	sig, _ := hex.DecodeString("01f685b0782021a25403b867fdac867da1e424cfb3ac19ebbd08a0fb134cbc42896aabcc00ca2b25bc762db03f7cead23e8b5f590a8e87690f0b6ec1552554ef")
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
	t.Log(hex.EncodeToString(crypto.Keccak256(result[:])[12:]))
	
}