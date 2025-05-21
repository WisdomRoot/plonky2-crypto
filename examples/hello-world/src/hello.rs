use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_crypto::hash::sha256::CircuitBuilderHashSha2;
use plonky2_crypto::hash::{CircuitBuilderHash, HashInputTarget, HashOutputTarget};

pub trait CircuitBuilderHello<F: RichField + Extendable<D>, const D: usize> {
    fn double_sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHello<F, D>
    for CircuitBuilder<F, D>
{
    fn double_sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget {
        // build the circuit for the first sha256
        let output1 = self.hash_sha256(input);

        // add an input target for the second sha256
        let input2 = self.add_virtual_hash_input_target(1, 512);

        // wire output1 to input2
        self.connect_hash_input(&input2, &output1, 0);

        // add a constant padding, since we know that output1 is 256-bit
        self.sha256_input_padding(&input2, 256);

        // build the circuit for the second sha256 and return the output
        self.hash_sha256(&input2)
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::*;
    use plonky2_crypto::hash::{keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R}, sha256::WitnessHashSha2};
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn test_keccak_sha256() {
        let tests = [
            [
                // 64 bytes input
                "",
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ],
            // [
            //     "...",
            //     "...",
            // ],
        ];
        let _ = env_logger::builder().format_timestamp(None).try_init();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // 0. create the circuit
        let target_input = builder.add_virtual_hash_input_target(1, KECCAK256_R);
        let target_output = builder.hash_keccak256(&target_input);
        let num_gates = builder.num_gates();
        builder.print_gate_counts(0);

        // 1. build circuit once
        let now = Instant::now();
        let data = builder.build::<C>();
        let time_build = now.elapsed();

        // 2. generate multiple ZKPs, one per test
        let mut time_prove = Duration::new(0, 0);
        let mut time_verify = Duration::new(0, 0);
        for t in tests {
            let input = hex::decode(t[0]).unwrap();
            let output = hex::decode(t[1]).unwrap();

            // set input/output
            let mut pw = PartialWitness::new();
            pw.set_keccak256_input_target(&target_input, &input).unwrap();
            pw.set_keccak256_output_target(&target_output, &output).unwrap();

            // generate proof
            let now = Instant::now();
            let proof = data.prove(pw).unwrap();
            let tmp = now.elapsed();

            time_prove += tmp;

            // verify proof
            data.verify(proof.clone()).unwrap();
            time_verify += now.elapsed() - tmp;

            println!("proof size: {:.2} KB", proof.to_bytes().len() as f64/1024.0);

            let pf = proof.compress(&data.verifier_only.circuit_digest, &data.common).unwrap();
            let pf_comp_size = pf.to_bytes().len() as f64/1024.0;
            println!("compress proof size: {:.2} KB", pf_comp_size);

            for g in data.common.gates.iter() {
                println!("({:?}): {}", g, g.0.num_constraints());
            }

        }
        time_prove /= tests.len() as u32;
        time_verify /= tests.len() as u32;
        println!(
            "sha3-256 num_gates={num_gates} time_build={time_build:?} time_prove={time_prove:?} time_verify={time_verify:?}"
        );


    }
}
