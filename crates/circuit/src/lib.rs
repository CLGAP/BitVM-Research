pub type WireId = usize;

pub enum Gate {
    And { a: WireId, b: WireId, out: WireId },
    Xor { a: WireId, b: WireId, out: WireId },
    Not { input: WireId, output: WireId },
 }

pub struct Circuit {
    pub num_wires: usize,
    pub input_wires: Vec<WireId>,
    pub output_wires: Vec<WireId>,
    pub gates: Vec<Gate>,
}

impl Circuit {
    pub fn new(input_wires: Vec<WireId>, output_wires: Vec<WireId>, gates: Vec<Gate>) -> Self {
        let num_wires = gates.iter().flat_map(|g| match g {
            Gate::And {a, b, out} | Gate::Xor { a, b, out } => vec![*a, *b, *out],
            Gate::Not { input, output} => vec![*input, *output],
        })
        .chain(input_wires.iter().copied())
        .chain(output_wires.iter().copied())
        .max().map(|m| m + 1).unwrap_or(0);

        Self { num_wires, input_wires, output_wires, gates }
    }

    pub fn evaluate(&self, input: &[bool]) -> Vec<bool> { //compare input with ciphertexts of src/garble-yao/src/lib.rs which has no booleans.
        assert_eq!(input.len(), self.input_wires.len(), "input length mismatch");
        
        let mut buf = vec![false; self.num_wires];

        for (i, &wire_id) in self.input_wires.iter().enumerate() {
            buf[wire_id] = input[i];
        }

        for gate in &self.gates {
            match gate {
                Gate::And { a, b, out } => buf[*out] = buf[*a] && buf[*b],
                Gate::Xor { a, b, out } => buf[*out] = buf[*a] ^ buf[*b],
                Gate::Not { input, output } => buf[*output] = !buf[*input],
            }
        }
        self.output_wires.iter().map(|&w| buf[w]).collect()
    }
}

pub mod fixtures {
    use crate::{Circuit, Gate};

    pub fn half_adder() -> Circuit {
        // wires: 0=a, 1=b, 2=sum (a XOR b), 3=carry (a AND b)
        Circuit::new(
            vec![0, 1],
            vec![2, 3],
            vec![
                Gate::Xor { a: 0, b: 1, out: 2 },
                Gate::And { a: 0, b: 1, out: 3 },
            ],
        )
    }

    pub fn and_gate() -> Circuit {
        Circuit::new(vec![0, 1], vec![2], vec![Gate::And { a: 0, b: 1, out: 2 }])
    }

    pub fn not_gate() -> Circuit {
        Circuit::new(vec![0], vec![1], vec![Gate::Not { input: 0, output: 1 }])
    }

    pub fn xor_and_not() -> Circuit {
        // (a XOR b) AND (NOT c)
        // wires: 0=a, 1=b, 2=c, 3=a^b, 4=!c, 5=output
        Circuit::new(
            vec![0, 1, 2],
            vec![5],
            vec![
                Gate::Xor { a: 0, b: 1, out: 3 },
                Gate::Not { input: 2, output: 4 },
                Gate::And { a: 3, b: 4, out: 5 },
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fixtures::*;
    
    #[test]
    fn half_adder_truth_table() {
        let c = half_adder();
        assert_eq!(c.evaluate(&[false, false]), vec![false, false]);
        assert_eq!(c.evaluate(&[false, true]), vec![true, false]);
        assert_eq!(c.evaluate(&[true, false]), vec![true, false]);
        assert_eq!(c.evaluate(&[true, true]), vec![false, true]);
    }

    #[test]
    fn not_gate_truth_table() {
        let c = not_gate();
        assert_eq!(c.evaluate(&[false]), vec![true]);
        assert_eq!(c.evaluate(&[true]), vec![false]);
    }
}
