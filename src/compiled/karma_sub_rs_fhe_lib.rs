
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


static LEVEL_0: [((usize, bool, CellType), &[GateInput]); 1] = [
    ((41, false, INV), &[Arg(0, 0)]),
];

static LEVEL_1: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((27, false, INV), &[Arg(1, 1)]),
    ((44, false, NAND2), &[Arg(1, 0), Tv(41)]),
    ((63, false, XNOR2), &[Arg(1, 1), Arg(0, 1)]),
];

static LEVEL_2: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((62, false, NAND2), &[Tv(27), Arg(0, 1)]),
    ((64, false, NAND2), &[Tv(44), Tv(63)]),
];

static LEVEL_3: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((28, false, INV), &[Arg(1, 2)]),
    ((65, false, NAND2), &[Tv(62), Tv(64)]),
    ((66, false, XNOR2), &[Arg(1, 2), Arg(0, 2)]),
];

static LEVEL_4: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((61, false, NAND2), &[Tv(28), Arg(0, 2)]),
    ((67, false, NAND2), &[Tv(65), Tv(66)]),
];

static LEVEL_5: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((29, false, INV), &[Arg(1, 3)]),
    ((68, false, NAND2), &[Tv(61), Tv(67)]),
    ((69, false, XNOR2), &[Arg(1, 3), Arg(0, 3)]),
];

static LEVEL_6: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((60, false, NAND2), &[Tv(29), Arg(0, 3)]),
    ((70, false, NAND2), &[Tv(68), Tv(69)]),
];

static LEVEL_7: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((30, false, INV), &[Arg(1, 4)]),
    ((71, false, NAND2), &[Tv(60), Tv(70)]),
    ((72, false, XNOR2), &[Arg(1, 4), Arg(0, 4)]),
];

static LEVEL_8: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((59, false, NAND2), &[Tv(30), Arg(0, 4)]),
    ((73, false, NAND2), &[Tv(71), Tv(72)]),
];

static LEVEL_9: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((31, false, INV), &[Arg(1, 5)]),
    ((74, false, NAND2), &[Tv(59), Tv(73)]),
    ((75, false, XNOR2), &[Arg(1, 5), Arg(0, 5)]),
];

static LEVEL_10: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((58, false, NAND2), &[Tv(31), Arg(0, 5)]),
    ((76, false, NAND2), &[Tv(74), Tv(75)]),
];

static LEVEL_11: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((32, false, INV), &[Arg(1, 6)]),
    ((57, false, XNOR2), &[Arg(1, 6), Arg(0, 6)]),
    ((0, false, NAND2), &[Tv(58), Tv(76)]),
];

static LEVEL_12: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((42, false, INV), &[Arg(0, 7)]),
    ((56, false, NAND2), &[Tv(32), Arg(0, 6)]),
    ((1, false, NAND2), &[Tv(57), Tv(0)]),
];

static LEVEL_13: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((33, false, INV), &[Arg(1, 7)]),
    ((55, false, NAND2), &[Arg(1, 7), Tv(42)]),
    ((2, false, NAND2), &[Tv(56), Tv(1)]),
];

static LEVEL_14: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((54, false, NAND2), &[Tv(33), Arg(0, 7)]),
    ((3, false, NAND2), &[Tv(55), Tv(2)]),
];

static LEVEL_15: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((34, false, INV), &[Arg(1, 8)]),
    ((53, false, XNOR2), &[Arg(1, 8), Arg(0, 8)]),
    ((4, false, NAND2), &[Tv(54), Tv(3)]),
];

static LEVEL_16: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((52, false, NAND2), &[Tv(34), Arg(0, 8)]),
    ((5, false, NAND2), &[Tv(53), Tv(4)]),
];

static LEVEL_17: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((35, false, INV), &[Arg(1, 9)]),
    ((6, false, NAND2), &[Tv(52), Tv(5)]),
    ((7, false, XNOR2), &[Arg(1, 9), Arg(0, 9)]),
];

static LEVEL_18: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((51, false, NAND2), &[Tv(35), Arg(0, 9)]),
    ((8, false, NAND2), &[Tv(6), Tv(7)]),
];

static LEVEL_19: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((36, false, INV), &[Arg(1, 10)]),
    ((50, false, XNOR2), &[Arg(1, 10), Arg(0, 10)]),
    ((9, false, NAND2), &[Tv(51), Tv(8)]),
];

static LEVEL_20: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((43, false, INV), &[Arg(0, 11)]),
    ((49, false, NAND2), &[Tv(36), Arg(0, 10)]),
    ((10, false, NAND2), &[Tv(50), Tv(9)]),
];

static LEVEL_21: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((37, false, INV), &[Arg(1, 11)]),
    ((48, false, NAND2), &[Arg(1, 11), Tv(43)]),
    ((11, false, NAND2), &[Tv(49), Tv(10)]),
];

static LEVEL_22: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((47, false, NAND2), &[Tv(37), Arg(0, 11)]),
    ((12, false, NAND2), &[Tv(48), Tv(11)]),
];

static LEVEL_23: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((38, false, INV), &[Arg(1, 12)]),
    ((46, false, XNOR2), &[Arg(1, 12), Arg(0, 12)]),
    ((13, false, NAND2), &[Tv(47), Tv(12)]),
];

static LEVEL_24: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((45, false, NAND2), &[Tv(38), Arg(0, 12)]),
    ((14, false, NAND2), &[Tv(46), Tv(13)]),
];

static LEVEL_25: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((39, false, INV), &[Arg(1, 13)]),
    ((15, false, NAND2), &[Tv(45), Tv(14)]),
    ((17, false, XNOR2), &[Arg(1, 13), Arg(0, 13)]),
];

static LEVEL_26: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((16, false, NAND2), &[Tv(39), Arg(0, 13)]),
    ((18, false, NAND2), &[Tv(15), Tv(17)]),
];

static LEVEL_27: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((40, false, INV), &[Arg(1, 14)]),
    ((19, false, NAND2), &[Tv(16), Tv(18)]),
    ((21, false, XNOR2), &[Arg(1, 14), Arg(0, 14)]),
];

static LEVEL_28: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((20, false, NAND2), &[Tv(40), Arg(0, 14)]),
    ((22, false, NAND2), &[Tv(19), Tv(21)]),
];

static LEVEL_29: [((usize, bool, CellType), &[GateInput]); 4] = [
    ((23, false, NAND2), &[Tv(20), Tv(22)]),
    ((24, false, XOR2), &[Arg(1, 15), Arg(0, 15)]),
    ((25, false, XOR2), &[Arg(1, 7), Arg(0, 7)]),
    ((26, false, XOR2), &[Arg(1, 11), Arg(0, 11)]),
];

static LEVEL_30: [((usize, bool, CellType), &[GateInput]); 16] = [
    ((0, true, XOR2), &[Arg(1, 0), Arg(0, 0)]),
    ((13, true, XOR2), &[Tv(15), Tv(17)]),
    ((14, true, XOR2), &[Tv(19), Tv(21)]),
    ((15, true, XNOR2), &[Tv(23), Tv(24)]),
    ((1, true, XOR2), &[Tv(44), Tv(63)]),
    ((2, true, XOR2), &[Tv(65), Tv(66)]),
    ((3, true, XOR2), &[Tv(68), Tv(69)]),
    ((4, true, XOR2), &[Tv(71), Tv(72)]),
    ((5, true, XOR2), &[Tv(74), Tv(75)]),
    ((6, true, XOR2), &[Tv(57), Tv(0)]),
    ((7, true, XNOR2), &[Tv(2), Tv(25)]),
    ((8, true, XOR2), &[Tv(53), Tv(4)]),
    ((9, true, XOR2), &[Tv(6), Tv(7)]),
    ((10, true, XOR2), &[Tv(50), Tv(9)]),
    ((11, true, XNOR2), &[Tv(11), Tv(26)]),
    ((12, true, XOR2), &[Tv(46), Tv(13)]),
];

static PRUNE_17: [usize; 2] = [
  52,
  5,
];

static PRUNE_30: [usize; 30] = [
  68,
  6,
  44,
  75,
  13,
  2,
  71,
  9,
  23,
  24,
  0,
  69,
  7,
  65,
  72,
  17,
  25,
  63,
  21,
  4,
  11,
  66,
  74,
  19,
  50,
  26,
  57,
  46,
  15,
  53,
];

static PRUNE_18: [usize; 1] = [
  35,
];

static PRUNE_6: [usize; 1] = [
  29,
];

static PRUNE_25: [usize; 2] = [
  45,
  14,
];

static PRUNE_13: [usize; 3] = [
  1,
  56,
  42,
];

static PRUNE_1: [usize; 1] = [
  41,
];

static PRUNE_20: [usize; 1] = [
  36,
];

static PRUNE_8: [usize; 1] = [
  30,
];

static PRUNE_2: [usize; 1] = [
  27,
];

static PRUNE_21: [usize; 3] = [
  10,
  49,
  43,
];

static PRUNE_9: [usize; 2] = [
  73,
  59,
];

static PRUNE_28: [usize; 1] = [
  40,
];

static PRUNE_16: [usize; 1] = [
  34,
];

static PRUNE_4: [usize; 1] = [
  28,
];

static PRUNE_23: [usize; 2] = [
  47,
  12,
];

static PRUNE_11: [usize; 2] = [
  76,
  58,
];

static PRUNE_5: [usize; 2] = [
  61,
  67,
];

static PRUNE_24: [usize; 1] = [
  38,
];

static PRUNE_12: [usize; 1] = [
  32,
];

static PRUNE_19: [usize; 2] = [
  51,
  8,
];

static PRUNE_7: [usize; 2] = [
  60,
  70,
];

static PRUNE_26: [usize; 1] = [
  39,
];

static PRUNE_14: [usize; 2] = [
  33,
  55,
];

static PRUNE_27: [usize; 2] = [
  16,
  18,
];

static PRUNE_3: [usize; 2] = [
  64,
  62,
];

static PRUNE_15: [usize; 2] = [
  54,
  3,
];

static PRUNE_22: [usize; 2] = [
  37,
  48,
];

static PRUNE_10: [usize; 1] = [
  31,
];

static PRUNE_29: [usize; 2] = [
  20,
  22,
];

fn prune(temp_nodes: &mut HashMap<usize, Ciphertext>, temp_node_ids: &[usize]) {
  for x in temp_node_ids {
    temp_nodes.remove(&x);
  }
}

pub fn karma_sub(a: &Vec<Ciphertext>, b: &Vec<Ciphertext>) -> Vec<Ciphertext> {
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
    prune(&mut temp_nodes, &PRUNE_1);
    run_level(&mut temp_nodes, &LEVEL_2);
    prune(&mut temp_nodes, &PRUNE_2);
    run_level(&mut temp_nodes, &LEVEL_3);
    prune(&mut temp_nodes, &PRUNE_3);
    run_level(&mut temp_nodes, &LEVEL_4);
    prune(&mut temp_nodes, &PRUNE_4);
    run_level(&mut temp_nodes, &LEVEL_5);
    prune(&mut temp_nodes, &PRUNE_5);
    run_level(&mut temp_nodes, &LEVEL_6);
    prune(&mut temp_nodes, &PRUNE_6);
    run_level(&mut temp_nodes, &LEVEL_7);
    prune(&mut temp_nodes, &PRUNE_7);
    run_level(&mut temp_nodes, &LEVEL_8);
    prune(&mut temp_nodes, &PRUNE_8);
    run_level(&mut temp_nodes, &LEVEL_9);
    prune(&mut temp_nodes, &PRUNE_9);
    run_level(&mut temp_nodes, &LEVEL_10);
    prune(&mut temp_nodes, &PRUNE_10);
    run_level(&mut temp_nodes, &LEVEL_11);
    prune(&mut temp_nodes, &PRUNE_11);
    run_level(&mut temp_nodes, &LEVEL_12);
    prune(&mut temp_nodes, &PRUNE_12);
    run_level(&mut temp_nodes, &LEVEL_13);
    prune(&mut temp_nodes, &PRUNE_13);
    run_level(&mut temp_nodes, &LEVEL_14);
    prune(&mut temp_nodes, &PRUNE_14);
    run_level(&mut temp_nodes, &LEVEL_15);
    prune(&mut temp_nodes, &PRUNE_15);
    run_level(&mut temp_nodes, &LEVEL_16);
    prune(&mut temp_nodes, &PRUNE_16);
    run_level(&mut temp_nodes, &LEVEL_17);
    prune(&mut temp_nodes, &PRUNE_17);
    run_level(&mut temp_nodes, &LEVEL_18);
    prune(&mut temp_nodes, &PRUNE_18);
    run_level(&mut temp_nodes, &LEVEL_19);
    prune(&mut temp_nodes, &PRUNE_19);
    run_level(&mut temp_nodes, &LEVEL_20);
    prune(&mut temp_nodes, &PRUNE_20);
    run_level(&mut temp_nodes, &LEVEL_21);
    prune(&mut temp_nodes, &PRUNE_21);
    run_level(&mut temp_nodes, &LEVEL_22);
    prune(&mut temp_nodes, &PRUNE_22);
    run_level(&mut temp_nodes, &LEVEL_23);
    prune(&mut temp_nodes, &PRUNE_23);
    run_level(&mut temp_nodes, &LEVEL_24);
    prune(&mut temp_nodes, &PRUNE_24);
    run_level(&mut temp_nodes, &LEVEL_25);
    prune(&mut temp_nodes, &PRUNE_25);
    run_level(&mut temp_nodes, &LEVEL_26);
    prune(&mut temp_nodes, &PRUNE_26);
    run_level(&mut temp_nodes, &LEVEL_27);
    prune(&mut temp_nodes, &PRUNE_27);
    run_level(&mut temp_nodes, &LEVEL_28);
    prune(&mut temp_nodes, &PRUNE_28);
    run_level(&mut temp_nodes, &LEVEL_29);
    prune(&mut temp_nodes, &PRUNE_29);
    run_level(&mut temp_nodes, &LEVEL_30);
    prune(&mut temp_nodes, &PRUNE_30);

            

                out.into_iter().map(|c| c.unwrap()).collect()
            }),
        )
        .unwrap()
}

