package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/xeipuuv/gojsonschema"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

const (
	// From https://tools.ietf.org/html/rfc5054#appendix-A
	generator = 2
	primeHex  = "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
)

type Proof struct {
	MMG     *(big.Int) `json:"modular-multiplicative-generator,string"`
	Prime   *(big.Int) `json:"prime,string"`
	Modhash *(big.Int) `json:"modular-hash,string"`
}

type JSONProof struct {
	MMG     string `json:"modular-multiplicative-generator"`
	Prime   string `json:"prime"`
	Modhash string `json:"modular-hash"`
}

func (p Proof) MarshalJSON() ([]byte, error) {
	m := map[string]string{
		"modular-multiplicative-generator": fmt.Sprintf("%x", p.MMG),
		"prime":                            fmt.Sprintf("%x", p.Prime),
		"modular-hash":                     fmt.Sprintf("%x", p.Modhash),
	}

	return json.Marshal(m)
}

/*
  - 2 parties that want to know if the intelligence signatures they have are the same, and hence they may be able to cooperate
  - In this case, they strictly do not want to show the other party what they have
	- providing they agree upon some schema for the data and a modulo-multiplicative generator pair
	-	we can then divide them, which through exponent laws will result in subtracting the 2
		hence g^0 == 1 if they are the same
*/
func Compare(ours []byte, proof *Proof) (bool, error) {
	p, success := new(big.Int).SetString(primeHex, 16)
	if !success {
		errors.New("Unable to initialize constant prime")
	}

	if proof.Prime.Cmp(p) != 0 || proof.MMG.Cmp(big.NewInt(generator)) != 0 {
		return false, errors.New("sender/receiver generator or prime didn't match")
	}

	ourHash := new(big.Int).SetBytes(ours)
	ourModhash := new(big.Int).Exp(big.NewInt(generator), ourHash, p)

	quot := new(big.Int).Div(proof.Modhash, ourModhash)
	if quot.Int64() != 1 {
		return false, nil
	}

	return true, nil
}

func Generate(fileHash []byte) *Proof {
	p, success := new(big.Int).SetString(primeHex, 16)
	if !success {
		panic("Unable to initialize constant prime")
	}

	proof := &Proof{
		MMG:     big.NewInt(generator),
		Prime:   p,
		Modhash: nil,
	}

	hash := new(big.Int).SetBytes(fileHash)
	proof.Modhash = new(big.Int).Exp(proof.MMG, hash, proof.Prime)

	return proof
}

// This is needed to use the json-schema libs
func uriFromRelative(file string) (string, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	fullpath := filepath.Join(pwd, file)
	return "file:///" + fullpath, nil
}

func main() {
	filePtr := flag.String("path", "", "path to json")
	modFilePtr := flag.String("cmpPath", "", "path to proof struct json")
	createProof := flag.Bool("createProof", false, "creates a generator and prime and your output proof based on your json")

	flag.Parse()

	if _, err := os.Stat(*filePtr); os.IsNotExist(err) {
		log.Fatalf("unable to locate file '%s'", *filePtr)
	}

	if *modFilePtr != "" {
		if _, err := os.Stat(*modFilePtr); os.IsNotExist(err) {
			log.Fatalf("unable to locate file '%s'", *modFilePtr)
		}
	}

	schemaUri, err := uriFromRelative("schema.json")
	if err != nil {
		log.Fatal(err)
	}
	schemaLoader := gojsonschema.NewReferenceLoader(schemaUri)

	jsonUri, err := uriFromRelative(*filePtr)
	if err != nil {
		log.Fatal(err)
	}
	documentLoader := gojsonschema.NewReferenceLoader(jsonUri)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		log.Fatal(err)
	}

	if result.Valid() {
		log.Println("The document is valid")
	} else {
		log.Println("The document is not valid. see errors :")
		for _, desc := range result.Errors() {
			log.Printf("- %s\n", desc)
		}
	}

	if *createProof {
		log.Println("Creating Proof")
		f, err := os.Open(*filePtr)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Fatal(err)
		}

		proof := Generate(h.Sum(nil))
		jsonStr, _ := json.Marshal(proof)
		log.Printf(string(jsonStr))
		os.Exit(0)
	}

	log.Println("loading intel file")
	f, err := os.Open(*filePtr)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	log.Println("deserializing proof")
	byteArr, err := ioutil.ReadFile(*modFilePtr)
	if err != nil {
		log.Fatal(err)
	}

	var jsonProof JSONProof
	err = json.Unmarshal(byteArr, &jsonProof)
	if err != nil {
		log.Fatal(err)
	}

	mmg, success := new(big.Int).SetString(jsonProof.MMG, 16)
	if !success {
		log.Fatal("unable to parse generator")
	}

	p, success := new(big.Int).SetString(jsonProof.Prime, 16)
	if !success {
		log.Fatal("unable to parse prime")
	}

	m, success := new(big.Int).SetString(jsonProof.Modhash, 16)
	if !success {
		log.Fatal("unable to parse modhash")
	}

	proof := &Proof{
		MMG:     mmg,
		Prime:   p,
		Modhash: m,
	}

	same, err := Compare(h.Sum(nil), proof)
	if err != nil {
		log.Fatal(err)
	}

	if same {
		log.Println("files matched")
		os.Exit(0)
	} else {
		log.Println("files did not match")
	}
}
