package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	snark "github.com/arnaucube/go-snark"
	"github.com/arnaucube/go-snark/circuitcompiler"
)

func panicErr(err error) {
	if err != nil {
		panic(err)
	}
}

func PrepareCircuit() string {

	flatCode := `
	func exp3(private a):
		b = a * a
		c = a * b
		return c

	func main(private s0, public s1):
		s3 = exp3(s0)
		s4 = s3 + s0
		s5 = s4 + 5
		equals(s1, s5)
		out = 1 * 1
	`
	return flatCode
}

func PrepareInputAndOutput() circuitcompiler.Inputs {

	input := `[
		3
	]
	`

	output := `[
		35
	]
	`

	var inputs circuitcompiler.Inputs
	err := json.Unmarshal([]byte(input), &inputs.Private)
	panicErr(err)
	err = json.Unmarshal([]byte(output), &inputs.Public)
	panicErr(err)

	return inputs

}

func CompileCircuit(flatCode string) circuitcompiler.Circuit {
	// parse the code

	parser := circuitcompiler.NewParser(strings.NewReader(flatCode))
	circuit, err := parser.Parse()
	panicErr(err)
	fmt.Println("circuit", circuit)

	a, b, c := circuit.GenerateR1CS()
	fmt.Println("\nR1CS:")
	fmt.Println("circuit.R1CS.A", a)
	fmt.Println("circuit.R1CS.B", b)
	fmt.Println("circuit.R1CS.C", c)

	return *circuit

}

func TrustedSetup(circuit circuitcompiler.Circuit) snark.Setup {

	// R1CS to QAP
	alphas, betas, gammas, _ := snark.Utils.PF.R1CSToQAP(circuit.R1CS.A, circuit.R1CS.B, circuit.R1CS.C)
	fmt.Println("QAP")
	fmt.Println(alphas)
	fmt.Println(betas)
	fmt.Println(gammas)

	// calculate trusted setup
	setup, err := snark.GenerateTrustedSetup(len(circuit.Signals), circuit, alphas, betas, gammas)
	panicErr(err)
	fmt.Println("\nt:", setup.Toxic.T)

	// remove setup.Toxic
	var tsetup snark.Setup
	tsetup.Pk = setup.Pk
	tsetup.Vk = setup.Vk

	return tsetup
}

func GenerateProofs(circuit circuitcompiler.Circuit, pk snark.Pk, inputs circuitcompiler.Inputs) snark.Proof {

	// calculate wittness
	witness, err := circuit.CalculateWitness(inputs.Private, inputs.Public)
	panicErr(err)
	fmt.Println("\nwitness", witness)

	// flat code to R1CS
	a := circuit.R1CS.A
	b := circuit.R1CS.B
	c := circuit.R1CS.C
	// R1CS to QAP
	alphas, betas, gammas, _ := snark.Utils.PF.R1CSToQAP(a, b, c)
	_, _, _, px := snark.Utils.PF.CombinePolynomials(witness, alphas, betas, gammas)
	hx := snark.Utils.PF.DivisorPolynomial(px, pk.Z)

	fmt.Println(circuit)
	fmt.Println(pk.G1T)
	fmt.Println(hx)
	fmt.Println(witness)
	proof, err := snark.GenerateProofs(circuit, pk, witness, px)
	panicErr(err)

	fmt.Println("\n proofs:")
	fmt.Println(proof)

	return proof
}

func VerifyProofs(vk snark.Vk, publicinputs []*big.Int, proof snark.Proof) bool {
	verified := snark.VerifyProof(vk, proof, publicinputs, true)
	return verified
}

func main() {

	//verifier
	flatCode := PrepareCircuit()

	circuit := CompileCircuit(flatCode)

	setup := TrustedSetup(circuit)

	pk := setup.Pk
	vk := setup.Vk

	//prover
	inputs := PrepareInputAndOutput()

	proof := GenerateProofs(circuit, pk, inputs)

	//verifier
	verified := VerifyProofs(vk, inputs.Public, proof)

	if !verified {
		fmt.Println("proofs not verified")
	} else {
		fmt.Println("Proofs verified")
	}

}
