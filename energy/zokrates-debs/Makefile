clean-rust:
	# Files generated during Rust compilation
	rm -rf target/

clean-zokrates:
	# Files generated during ZoKrates compilation & set-up
	rm -f src/*.tmp.zok *.out *.abi.json *.r1cs *.ztf *.proving.key *.verification.key

clean-proof:
	# Files generated during ZoKrates execution & proving
	rm -f *.wtns *.witness *.proof.json challenge1.*.json historical.*.json
