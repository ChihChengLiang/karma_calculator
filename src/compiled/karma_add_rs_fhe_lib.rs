
use rayon::prelude::*;
use std::collections::HashMap;

use phantom_zone::*;

type Ciphertext = FheBool;

enum GateInput {
    Arg(usize, usize), // arg + index
    Output(usize), // reuse of output wire
    Tv(usize),  // temp value
    Cst(bool),  // constant
}

use GateInput::*;

#[derive(PartialEq, Eq, Hash)]
enum CellType {
    AND2,
    NAND2,
    XOR2,
    XNOR2,
    OR2,
    NOR2,
    INV,
    // TODO: Add back MUX2
}

use CellType::*;


static LEVEL_0: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((27, false, AND2), &[Arg(0, 0), Arg(1, 0)]),
    ((28, false, XOR2), &[Arg(0, 1), Arg(1, 1)]),
];

static LEVEL_1: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((26, false, NAND2), &[Arg(0, 1), Arg(1, 1)]),
    ((29, false, NAND2), &[Tv(27), Tv(28)]),
];

static LEVEL_2: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((30, false, NAND2), &[Tv(26), Tv(29)]),
    ((31, false, XOR2), &[Arg(0, 2), Arg(1, 2)]),
];

static LEVEL_3: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((25, false, NAND2), &[Arg(0, 2), Arg(1, 2)]),
    ((32, false, NAND2), &[Tv(30), Tv(31)]),
];

static LEVEL_4: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((33, false, NAND2), &[Tv(25), Tv(32)]),
    ((34, false, XOR2), &[Arg(0, 3), Arg(1, 3)]),
];

static LEVEL_5: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((24, false, NAND2), &[Arg(0, 3), Arg(1, 3)]),
    ((35, false, NAND2), &[Tv(33), Tv(34)]),
];

static LEVEL_6: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((36, false, NAND2), &[Tv(24), Tv(35)]),
    ((37, false, XOR2), &[Arg(0, 4), Arg(1, 4)]),
];

static LEVEL_7: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((23, false, NAND2), &[Arg(0, 4), Arg(1, 4)]),
    ((38, false, NAND2), &[Tv(36), Tv(37)]),
];

static LEVEL_8: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((39, false, NAND2), &[Tv(23), Tv(38)]),
    ((40, false, XOR2), &[Arg(0, 5), Arg(1, 5)]),
];

static LEVEL_9: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((22, false, NAND2), &[Arg(0, 5), Arg(1, 5)]),
    ((41, false, NAND2), &[Tv(39), Tv(40)]),
];

static LEVEL_10: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((21, false, XOR2), &[Arg(0, 6), Arg(1, 6)]),
    ((42, false, NAND2), &[Tv(22), Tv(41)]),
];

static LEVEL_11: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((20, false, NAND2), &[Arg(0, 6), Arg(1, 6)]),
    ((43, false, NAND2), &[Tv(21), Tv(42)]),
];

static LEVEL_12: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((19, false, OR2), &[Arg(0, 7), Arg(1, 7)]),
    ((44, false, NAND2), &[Tv(20), Tv(43)]),
];

static LEVEL_13: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((18, false, NAND2), &[Arg(0, 7), Arg(1, 7)]),
    ((45, false, NAND2), &[Tv(19), Tv(44)]),
];

static LEVEL_14: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((17, false, XOR2), &[Arg(0, 8), Arg(1, 8)]),
    ((46, false, NAND2), &[Tv(18), Tv(45)]),
];

static LEVEL_15: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((16, false, NAND2), &[Arg(0, 8), Arg(1, 8)]),
    ((47, false, NAND2), &[Tv(17), Tv(46)]),
];

static LEVEL_16: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((48, false, NAND2), &[Tv(16), Tv(47)]),
    ((49, false, XOR2), &[Arg(0, 9), Arg(1, 9)]),
];

static LEVEL_17: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((15, false, NAND2), &[Arg(0, 9), Arg(1, 9)]),
    ((50, false, NAND2), &[Tv(48), Tv(49)]),
];

static LEVEL_18: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((14, false, XOR2), &[Arg(0, 10), Arg(1, 10)]),
    ((51, false, NAND2), &[Tv(15), Tv(50)]),
];

static LEVEL_19: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((13, false, NAND2), &[Arg(0, 10), Arg(1, 10)]),
    ((52, false, NAND2), &[Tv(14), Tv(51)]),
];

static LEVEL_20: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((12, false, OR2), &[Arg(0, 11), Arg(1, 11)]),
    ((53, false, NAND2), &[Tv(13), Tv(52)]),
];

static LEVEL_21: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((11, false, NAND2), &[Arg(0, 11), Arg(1, 11)]),
    ((54, false, NAND2), &[Tv(12), Tv(53)]),
];

static LEVEL_22: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((10, false, XOR2), &[Arg(0, 12), Arg(1, 12)]),
    ((55, false, NAND2), &[Tv(11), Tv(54)]),
];

static LEVEL_23: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((9, false, NAND2), &[Arg(0, 12), Arg(1, 12)]),
    ((56, false, NAND2), &[Tv(10), Tv(55)]),
];

static LEVEL_24: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((57, false, NAND2), &[Tv(9), Tv(56)]),
    ((59, false, XOR2), &[Arg(0, 13), Arg(1, 13)]),
];

static LEVEL_25: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((58, false, NAND2), &[Arg(0, 13), Arg(1, 13)]),
    ((0, false, NAND2), &[Tv(57), Tv(59)]),
];

static LEVEL_26: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((1, false, NAND2), &[Tv(58), Tv(0)]),
    ((3, false, XOR2), &[Arg(0, 14), Arg(1, 14)]),
];

static LEVEL_27: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((2, false, NAND2), &[Arg(0, 14), Arg(1, 14)]),
    ((4, false, NAND2), &[Tv(1), Tv(3)]),
];

static LEVEL_28: [((usize, bool, CellType), &[GateInput]); 4] = [
    ((5, false, NAND2), &[Tv(2), Tv(4)]),
    ((6, false, XNOR2), &[Arg(0, 15), Arg(1, 15)]),
    ((7, false, XNOR2), &[Arg(0, 7), Arg(1, 7)]),
    ((8, false, XNOR2), &[Arg(0, 11), Arg(1, 11)]),
];

static LEVEL_29: [((usize, bool, CellType), &[GateInput]); 16] = [
    ((13, true, XOR2), &[Tv(57), Tv(59)]),
    ((14, true, XOR2), &[Tv(1), Tv(3)]),
    ((15, true, XNOR2), &[Tv(5), Tv(6)]),
    ((0, true, XOR2), &[Arg(0, 0), Arg(1, 0)]),
    ((1, true, XOR2), &[Tv(27), Tv(28)]),
    ((2, true, XOR2), &[Tv(30), Tv(31)]),
    ((3, true, XOR2), &[Tv(33), Tv(34)]),
    ((4, true, XOR2), &[Tv(36), Tv(37)]),
    ((5, true, XOR2), &[Tv(39), Tv(40)]),
    ((6, true, XOR2), &[Tv(21), Tv(42)]),
    ((7, true, XNOR2), &[Tv(44), Tv(7)]),
    ((8, true, XOR2), &[Tv(17), Tv(46)]),
    ((9, true, XOR2), &[Tv(48), Tv(49)]),
    ((10, true, XOR2), &[Tv(14), Tv(51)]),
    ((11, true, XNOR2), &[Tv(53), Tv(8)]),
    ((12, true, XOR2), &[Tv(10), Tv(55)]),
];

static PRUNE_18: [usize; 2] = [
  50,
  15,
];

static PRUNE_24: [usize; 2] = [
  9,
  56,
];

static PRUNE_29: [usize; 30] = [
  36,
  5,
  57,
  39,
  46,
  53,
  30,
  37,
  44,
  6,
  51,
  33,
  40,
  55,
  31,
  7,
  14,
  27,
  34,
  3,
  10,
  17,
  48,
  49,
  1,
  8,
  21,
  28,
  59,
  42,
];

static PRUNE_6: [usize; 2] = [
  24,
  35,
];

static PRUNE_12: [usize; 2] = [
  43,
  20,
];

static PRUNE_13: [usize; 1] = [
  19,
];

static PRUNE_8: [usize; 2] = [
  23,
  38,
];

static PRUNE_14: [usize; 2] = [
  45,
  18,
];

static PRUNE_20: [usize; 2] = [
  13,
  52,
];

static PRUNE_26: [usize; 2] = [
  0,
  58,
];

static PRUNE_21: [usize; 1] = [
  12,
];

static PRUNE_2: [usize; 2] = [
  26,
  29,
];

static PRUNE_28: [usize; 2] = [
  2,
  4,
];

static PRUNE_4: [usize; 2] = [
  25,
  32,
];

static PRUNE_10: [usize; 2] = [
  22,
  41,
];

static PRUNE_16: [usize; 2] = [
  16,
  47,
];

static PRUNE_22: [usize; 2] = [
  54,
  11,
];

fn prune(temp_nodes: &mut HashMap<usize, Ciphertext>, temp_node_ids: &[usize]) {
  for x in temp_node_ids {
    temp_nodes.remove(&x);
  }
}

pub fn karma_add(a: &Vec<Ciphertext>, b: &Vec<Ciphertext>) -> Vec<Ciphertext> {
    let parameter_set = get_active_parameter_set();
    rayon::ThreadPoolBuilder::new()
        .build_scoped(
            |thread| {
                set_parameter_set(parameter_set);
                thread.run()
            },
            |pool| pool.install(|| {

                let args: &[&Vec<Ciphertext>] = &[a, b];

                let mut temp_nodes = HashMap::new();
                let mut out = Vec::new();
                out.resize(16, None);

                let mut run_level = |
                temp_nodes: &mut HashMap<usize, Ciphertext>,
                tasks: &[((usize, bool, CellType), &[GateInput])]
                | {
                    let updates = tasks
                        .into_par_iter()
                        .map(|(k, task_args)| {
                            let (id, is_output, celltype) = k;
                            let task_args = task_args.into_iter()
                            .map(|arg| match arg {
                                Cst(false) => todo!(),
                                Cst(true) => todo!(),
                                Arg(pos, ndx) => &args[*pos][*ndx],
                                Tv(ndx) => &temp_nodes[ndx],
                                Output(ndx) => &out[*ndx]
                                            .as_ref()
                                            .expect(&format!("Output node {ndx} not found")),
                            }).collect::<Vec<_>>();

                            let gate_func = |args: &[&Ciphertext]| match celltype {
                                AND2 => args[0] & args[1],
                                NAND2 => args[0].nand(args[1]),
                                OR2 => args[0] | args[1],
                                NOR2 => args[0].nor(args[1]),
                                XOR2 => args[0] ^ args[1],
                                XNOR2 => args[0].xnor(args[1]),
                                INV => !args[0],
                            };
                            
                            ((*id, *is_output), gate_func(&task_args))
                        })
                        .collect::<Vec<_>>();
                    updates.into_iter().for_each(|(k, v)| {
                        let (index, is_output) = k;
                        if is_output {
                            out[index] = Some(v);
                        } else {
                            temp_nodes.insert(index, v);
                        }
                    });
                };

                run_level(&mut temp_nodes, &LEVEL_0);
    run_level(&mut temp_nodes, &LEVEL_1);
    run_level(&mut temp_nodes, &LEVEL_2);
    prune(&mut temp_nodes, &PRUNE_2);
    run_level(&mut temp_nodes, &LEVEL_3);
    run_level(&mut temp_nodes, &LEVEL_4);
    prune(&mut temp_nodes, &PRUNE_4);
    run_level(&mut temp_nodes, &LEVEL_5);
    run_level(&mut temp_nodes, &LEVEL_6);
    prune(&mut temp_nodes, &PRUNE_6);
    run_level(&mut temp_nodes, &LEVEL_7);
    run_level(&mut temp_nodes, &LEVEL_8);
    prune(&mut temp_nodes, &PRUNE_8);
    run_level(&mut temp_nodes, &LEVEL_9);
    run_level(&mut temp_nodes, &LEVEL_10);
    prune(&mut temp_nodes, &PRUNE_10);
    run_level(&mut temp_nodes, &LEVEL_11);
    run_level(&mut temp_nodes, &LEVEL_12);
    prune(&mut temp_nodes, &PRUNE_12);
    run_level(&mut temp_nodes, &LEVEL_13);
    prune(&mut temp_nodes, &PRUNE_13);
    run_level(&mut temp_nodes, &LEVEL_14);
    prune(&mut temp_nodes, &PRUNE_14);
    run_level(&mut temp_nodes, &LEVEL_15);
    run_level(&mut temp_nodes, &LEVEL_16);
    prune(&mut temp_nodes, &PRUNE_16);
    run_level(&mut temp_nodes, &LEVEL_17);
    run_level(&mut temp_nodes, &LEVEL_18);
    prune(&mut temp_nodes, &PRUNE_18);
    run_level(&mut temp_nodes, &LEVEL_19);
    run_level(&mut temp_nodes, &LEVEL_20);
    prune(&mut temp_nodes, &PRUNE_20);
    run_level(&mut temp_nodes, &LEVEL_21);
    prune(&mut temp_nodes, &PRUNE_21);
    run_level(&mut temp_nodes, &LEVEL_22);
    prune(&mut temp_nodes, &PRUNE_22);
    run_level(&mut temp_nodes, &LEVEL_23);
    run_level(&mut temp_nodes, &LEVEL_24);
    prune(&mut temp_nodes, &PRUNE_24);
    run_level(&mut temp_nodes, &LEVEL_25);
    run_level(&mut temp_nodes, &LEVEL_26);
    prune(&mut temp_nodes, &PRUNE_26);
    run_level(&mut temp_nodes, &LEVEL_27);
    run_level(&mut temp_nodes, &LEVEL_28);
    prune(&mut temp_nodes, &PRUNE_28);
    run_level(&mut temp_nodes, &LEVEL_29);
    prune(&mut temp_nodes, &PRUNE_29);

            

                out.into_iter().map(|c| c.unwrap()).collect()
            }),
        )
        .unwrap()
}

