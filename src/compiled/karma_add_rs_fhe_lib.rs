
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
    ((16, false, AND2), &[Arg(0, 0), Arg(1, 0)]),
    ((17, false, XOR2), &[Arg(0, 1), Arg(1, 1)]),
];

static LEVEL_1: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((15, false, NAND2), &[Arg(0, 1), Arg(1, 1)]),
    ((18, false, NAND2), &[Tv(16), Tv(17)]),
];

static LEVEL_2: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((19, false, NAND2), &[Tv(15), Tv(18)]),
    ((20, false, XOR2), &[Arg(0, 2), Arg(1, 2)]),
];

static LEVEL_3: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((14, false, NAND2), &[Arg(0, 2), Arg(1, 2)]),
    ((21, false, NAND2), &[Tv(19), Tv(20)]),
];

static LEVEL_4: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((22, false, NAND2), &[Tv(14), Tv(21)]),
    ((23, false, XOR2), &[Arg(0, 3), Arg(1, 3)]),
];

static LEVEL_5: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((13, false, NAND2), &[Arg(0, 3), Arg(1, 3)]),
    ((24, false, NAND2), &[Tv(22), Tv(23)]),
];

static LEVEL_6: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((25, false, NAND2), &[Tv(13), Tv(24)]),
    ((26, false, XOR2), &[Arg(0, 4), Arg(1, 4)]),
];

static LEVEL_7: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((12, false, NAND2), &[Arg(0, 4), Arg(1, 4)]),
    ((27, false, NAND2), &[Tv(25), Tv(26)]),
];

static LEVEL_8: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((28, false, NAND2), &[Tv(12), Tv(27)]),
    ((29, false, XOR2), &[Arg(0, 5), Arg(1, 5)]),
];

static LEVEL_9: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((11, false, NAND2), &[Arg(0, 5), Arg(1, 5)]),
    ((30, false, NAND2), &[Tv(28), Tv(29)]),
];

static LEVEL_10: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((10, false, XOR2), &[Arg(0, 6), Arg(1, 6)]),
    ((31, false, NAND2), &[Tv(11), Tv(30)]),
];

static LEVEL_11: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((9, false, NAND2), &[Arg(0, 6), Arg(1, 6)]),
    ((32, false, NAND2), &[Tv(10), Tv(31)]),
];

static LEVEL_12: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((8, false, OR2), &[Arg(0, 7), Arg(1, 7)]),
    ((33, false, NAND2), &[Tv(9), Tv(32)]),
];

static LEVEL_13: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((7, false, NAND2), &[Arg(0, 7), Arg(1, 7)]),
    ((34, false, NAND2), &[Tv(8), Tv(33)]),
];

static LEVEL_14: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((6, false, XOR2), &[Arg(0, 8), Arg(1, 8)]),
    ((35, false, NAND2), &[Tv(7), Tv(34)]),
];

static LEVEL_15: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((5, false, NAND2), &[Arg(0, 8), Arg(1, 8)]),
    ((36, false, NAND2), &[Tv(6), Tv(35)]),
];

static LEVEL_16: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((4, false, OR2), &[Arg(0, 9), Arg(1, 9)]),
    ((37, false, NAND2), &[Tv(5), Tv(36)]),
];

static LEVEL_17: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((3, false, NAND2), &[Arg(0, 9), Arg(1, 9)]),
    ((38, false, NAND2), &[Tv(4), Tv(37)]),
];

static LEVEL_18: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((2, false, XOR2), &[Arg(0, 10), Arg(1, 10)]),
    ((39, false, NAND2), &[Tv(3), Tv(38)]),
];

static LEVEL_19: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((1, false, NAND2), &[Arg(0, 10), Arg(1, 10)]),
    ((40, false, NAND2), &[Tv(2), Tv(39)]),
];

static LEVEL_20: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((0, false, OR2), &[Arg(0, 11), Arg(1, 11)]),
    ((41, false, NAND2), &[Tv(1), Tv(40)]),
];

static LEVEL_21: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((132, false, NAND2), &[Arg(0, 11), Arg(1, 11)]),
    ((42, false, NAND2), &[Tv(0), Tv(41)]),
];

static LEVEL_22: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((131, false, XOR2), &[Arg(0, 12), Arg(1, 12)]),
    ((43, false, NAND2), &[Tv(132), Tv(42)]),
];

static LEVEL_23: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((130, false, NAND2), &[Arg(0, 12), Arg(1, 12)]),
    ((44, false, NAND2), &[Tv(131), Tv(43)]),
];

static LEVEL_24: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((45, false, AND2), &[Tv(130), Tv(44)]),
    ((46, false, NAND2), &[Arg(0, 13), Arg(1, 13)]),
];

static LEVEL_25: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((47, false, OR2), &[Arg(0, 13), Arg(1, 13)]),
    ((51, false, NAND2), &[Tv(45), Tv(46)]),
];

static LEVEL_26: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((50, false, XOR2), &[Arg(0, 14), Arg(1, 14)]),
    ((52, false, AND2), &[Tv(47), Tv(51)]),
];

static LEVEL_27: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((49, false, NAND2), &[Arg(0, 14), Arg(1, 14)]),
    ((53, false, NAND2), &[Tv(50), Tv(52)]),
];

static LEVEL_28: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((54, false, AND2), &[Tv(49), Tv(53)]),
    ((55, false, NAND2), &[Arg(0, 15), Arg(1, 15)]),
];

static LEVEL_29: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((56, false, OR2), &[Arg(0, 15), Arg(1, 15)]),
    ((60, false, NAND2), &[Tv(54), Tv(55)]),
];

static LEVEL_30: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((59, false, XOR2), &[Arg(0, 16), Arg(1, 16)]),
    ((61, false, AND2), &[Tv(56), Tv(60)]),
];

static LEVEL_31: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((58, false, NAND2), &[Arg(0, 16), Arg(1, 16)]),
    ((62, false, NAND2), &[Tv(59), Tv(61)]),
];

static LEVEL_32: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((63, false, AND2), &[Tv(58), Tv(62)]),
    ((64, false, NAND2), &[Arg(0, 17), Arg(1, 17)]),
];

static LEVEL_33: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((65, false, OR2), &[Arg(0, 17), Arg(1, 17)]),
    ((69, false, NAND2), &[Tv(63), Tv(64)]),
];

static LEVEL_34: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((68, false, XOR2), &[Arg(0, 18), Arg(1, 18)]),
    ((70, false, AND2), &[Tv(65), Tv(69)]),
];

static LEVEL_35: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((67, false, NAND2), &[Arg(0, 18), Arg(1, 18)]),
    ((71, false, NAND2), &[Tv(68), Tv(70)]),
];

static LEVEL_36: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((72, false, AND2), &[Tv(67), Tv(71)]),
    ((73, false, NAND2), &[Arg(0, 19), Arg(1, 19)]),
];

static LEVEL_37: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((74, false, OR2), &[Arg(0, 19), Arg(1, 19)]),
    ((78, false, NAND2), &[Tv(72), Tv(73)]),
];

static LEVEL_38: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((77, false, XOR2), &[Arg(0, 20), Arg(1, 20)]),
    ((79, false, AND2), &[Tv(74), Tv(78)]),
];

static LEVEL_39: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((76, false, NAND2), &[Arg(0, 20), Arg(1, 20)]),
    ((80, false, NAND2), &[Tv(77), Tv(79)]),
];

static LEVEL_40: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((81, false, AND2), &[Tv(76), Tv(80)]),
    ((82, false, NAND2), &[Arg(0, 21), Arg(1, 21)]),
];

static LEVEL_41: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((83, false, OR2), &[Arg(0, 21), Arg(1, 21)]),
    ((87, false, NAND2), &[Tv(81), Tv(82)]),
];

static LEVEL_42: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((86, false, XOR2), &[Arg(0, 22), Arg(1, 22)]),
    ((88, false, AND2), &[Tv(83), Tv(87)]),
];

static LEVEL_43: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((85, false, NAND2), &[Arg(0, 22), Arg(1, 22)]),
    ((89, false, NAND2), &[Tv(86), Tv(88)]),
];

static LEVEL_44: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((90, false, AND2), &[Tv(85), Tv(89)]),
    ((91, false, NAND2), &[Arg(0, 23), Arg(1, 23)]),
];

static LEVEL_45: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((92, false, OR2), &[Arg(0, 23), Arg(1, 23)]),
    ((96, false, NAND2), &[Tv(90), Tv(91)]),
];

static LEVEL_46: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((95, false, XOR2), &[Arg(0, 24), Arg(1, 24)]),
    ((97, false, AND2), &[Tv(92), Tv(96)]),
];

static LEVEL_47: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((94, false, NAND2), &[Arg(0, 24), Arg(1, 24)]),
    ((98, false, NAND2), &[Tv(95), Tv(97)]),
];

static LEVEL_48: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((99, false, AND2), &[Tv(94), Tv(98)]),
    ((100, false, NAND2), &[Arg(0, 25), Arg(1, 25)]),
];

static LEVEL_49: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((101, false, OR2), &[Arg(0, 25), Arg(1, 25)]),
    ((105, false, NAND2), &[Tv(99), Tv(100)]),
];

static LEVEL_50: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((104, false, XOR2), &[Arg(0, 26), Arg(1, 26)]),
    ((106, false, AND2), &[Tv(101), Tv(105)]),
];

static LEVEL_51: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((103, false, NAND2), &[Arg(0, 26), Arg(1, 26)]),
    ((107, false, NAND2), &[Tv(104), Tv(106)]),
];

static LEVEL_52: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((108, false, AND2), &[Tv(103), Tv(107)]),
    ((109, false, NAND2), &[Arg(0, 27), Arg(1, 27)]),
];

static LEVEL_53: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((110, false, OR2), &[Arg(0, 27), Arg(1, 27)]),
    ((114, false, NAND2), &[Tv(108), Tv(109)]),
];

static LEVEL_54: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((113, false, XOR2), &[Arg(0, 28), Arg(1, 28)]),
    ((115, false, AND2), &[Tv(110), Tv(114)]),
];

static LEVEL_55: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((112, false, NAND2), &[Arg(0, 28), Arg(1, 28)]),
    ((116, false, NAND2), &[Tv(113), Tv(115)]),
];

static LEVEL_56: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((117, false, NAND2), &[Tv(112), Tv(116)]),
    ((119, false, XOR2), &[Arg(0, 29), Arg(1, 29)]),
];

static LEVEL_57: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((118, false, NAND2), &[Arg(0, 29), Arg(1, 29)]),
    ((120, false, NAND2), &[Tv(117), Tv(119)]),
];

static LEVEL_58: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((121, false, NAND2), &[Tv(118), Tv(120)]),
    ((123, false, XOR2), &[Arg(0, 30), Arg(1, 30)]),
];

static LEVEL_59: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((122, false, NAND2), &[Arg(0, 30), Arg(1, 30)]),
    ((124, false, NAND2), &[Tv(121), Tv(123)]),
];

static LEVEL_60: [((usize, bool, CellType), &[GateInput]); 13] = [
    ((48, false, XOR2), &[Arg(0, 13), Arg(1, 13)]),
    ((57, false, XOR2), &[Arg(0, 15), Arg(1, 15)]),
    ((66, false, XOR2), &[Arg(0, 17), Arg(1, 17)]),
    ((75, false, XOR2), &[Arg(0, 19), Arg(1, 19)]),
    ((84, false, XOR2), &[Arg(0, 21), Arg(1, 21)]),
    ((93, false, XOR2), &[Arg(0, 23), Arg(1, 23)]),
    ((102, false, XOR2), &[Arg(0, 25), Arg(1, 25)]),
    ((111, false, XOR2), &[Arg(0, 27), Arg(1, 27)]),
    ((125, false, NAND2), &[Tv(122), Tv(124)]),
    ((126, false, XNOR2), &[Arg(0, 31), Arg(1, 31)]),
    ((127, false, XNOR2), &[Arg(0, 7), Arg(1, 7)]),
    ((128, false, XNOR2), &[Arg(0, 9), Arg(1, 9)]),
    ((129, false, XNOR2), &[Arg(0, 11), Arg(1, 11)]),
];

static LEVEL_61: [((usize, bool, CellType), &[GateInput]); 32] = [
    ((13, true, XNOR2), &[Tv(45), Tv(48)]),
    ((14, true, XOR2), &[Tv(50), Tv(52)]),
    ((15, true, XNOR2), &[Tv(54), Tv(57)]),
    ((16, true, XOR2), &[Tv(59), Tv(61)]),
    ((17, true, XNOR2), &[Tv(63), Tv(66)]),
    ((18, true, XOR2), &[Tv(68), Tv(70)]),
    ((19, true, XNOR2), &[Tv(72), Tv(75)]),
    ((20, true, XOR2), &[Tv(77), Tv(79)]),
    ((21, true, XNOR2), &[Tv(81), Tv(84)]),
    ((22, true, XOR2), &[Tv(86), Tv(88)]),
    ((23, true, XNOR2), &[Tv(90), Tv(93)]),
    ((24, true, XOR2), &[Tv(95), Tv(97)]),
    ((25, true, XNOR2), &[Tv(99), Tv(102)]),
    ((26, true, XOR2), &[Tv(104), Tv(106)]),
    ((27, true, XNOR2), &[Tv(108), Tv(111)]),
    ((28, true, XOR2), &[Tv(113), Tv(115)]),
    ((29, true, XOR2), &[Tv(117), Tv(119)]),
    ((30, true, XOR2), &[Tv(121), Tv(123)]),
    ((31, true, XNOR2), &[Tv(125), Tv(126)]),
    ((0, true, XOR2), &[Arg(0, 0), Arg(1, 0)]),
    ((1, true, XOR2), &[Tv(16), Tv(17)]),
    ((2, true, XOR2), &[Tv(19), Tv(20)]),
    ((3, true, XOR2), &[Tv(22), Tv(23)]),
    ((4, true, XOR2), &[Tv(25), Tv(26)]),
    ((5, true, XOR2), &[Tv(28), Tv(29)]),
    ((6, true, XOR2), &[Tv(10), Tv(31)]),
    ((7, true, XNOR2), &[Tv(33), Tv(127)]),
    ((8, true, XOR2), &[Tv(6), Tv(35)]),
    ((9, true, XNOR2), &[Tv(37), Tv(128)]),
    ((10, true, XOR2), &[Tv(2), Tv(39)]),
    ((11, true, XNOR2), &[Tv(41), Tv(129)]),
    ((12, true, XOR2), &[Tv(131), Tv(43)]),
];

static PRUNE_53: [usize; 1] = [
  109,
];

static PRUNE_22: [usize; 2] = [
  132,
  42,
];

static PRUNE_10: [usize; 2] = [
  30,
  11,
];

static PRUNE_41: [usize; 1] = [
  82,
];

static PRUNE_29: [usize; 1] = [
  55,
];

static PRUNE_60: [usize; 2] = [
  124,
  122,
];

static PRUNE_48: [usize; 2] = [
  98,
  94,
];

static PRUNE_25: [usize; 1] = [
  46,
];

static PRUNE_17: [usize; 1] = [
  4,
];

static PRUNE_58: [usize; 2] = [
  120,
  118,
];

static PRUNE_46: [usize; 2] = [
  92,
  96,
];

static PRUNE_34: [usize; 2] = [
  69,
  65,
];

static PRUNE_50: [usize; 2] = [
  101,
  105,
];

static PRUNE_38: [usize; 2] = [
  78,
  74,
];

static PRUNE_26: [usize; 2] = [
  47,
  51,
];

static PRUNE_14: [usize; 2] = [
  7,
  34,
];

static PRUNE_45: [usize; 1] = [
  91,
];

static PRUNE_36: [usize; 2] = [
  67,
  71,
];

static PRUNE_24: [usize; 2] = [
  44,
  130,
];

static PRUNE_12: [usize; 2] = [
  9,
  32,
];

static PRUNE_16: [usize; 2] = [
  5,
  36,
];

static PRUNE_4: [usize; 2] = [
  14,
  21,
];

static PRUNE_54: [usize; 2] = [
  110,
  114,
];

static PRUNE_42: [usize; 2] = [
  87,
  83,
];

static PRUNE_2: [usize; 2] = [
  15,
  18,
];

static PRUNE_33: [usize; 1] = [
  64,
];

static PRUNE_52: [usize; 2] = [
  103,
  107,
];

static PRUNE_21: [usize; 1] = [
  0,
];

static PRUNE_40: [usize; 2] = [
  80,
  76,
];

static PRUNE_28: [usize; 2] = [
  53,
  49,
];

static PRUNE_56: [usize; 2] = [
  112,
  116,
];

static PRUNE_13: [usize; 1] = [
  8,
];

static PRUNE_44: [usize; 2] = [
  89,
  85,
];

static PRUNE_32: [usize; 2] = [
  58,
  62,
];

static PRUNE_20: [usize; 2] = [
  40,
  1,
];

static PRUNE_8: [usize; 2] = [
  27,
  12,
];

static PRUNE_30: [usize; 2] = [
  56,
  60,
];

static PRUNE_61: [usize; 62] = [
  10,
  41,
  72,
  111,
  131,
  86,
  117,
  16,
  95,
  126,
  2,
  33,
  106,
  75,
  61,
  123,
  115,
  22,
  84,
  39,
  70,
  19,
  50,
  81,
  129,
  90,
  121,
  28,
  59,
  104,
  25,
  127,
  17,
  79,
  48,
  93,
  45,
  31,
  54,
  23,
  102,
  113,
  20,
  68,
  99,
  6,
  37,
  29,
  77,
  108,
  88,
  119,
  26,
  57,
  43,
  35,
  97,
  66,
  128,
  52,
  63,
  125,
];

static PRUNE_18: [usize; 2] = [
  38,
  3,
];

static PRUNE_49: [usize; 1] = [
  100,
];

static PRUNE_6: [usize; 2] = [
  24,
  13,
];

static PRUNE_37: [usize; 1] = [
  73,
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
                out.resize(32, None);

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
    prune(&mut temp_nodes, &PRUNE_17);
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
    prune(&mut temp_nodes, &PRUNE_25);
    run_level(&mut temp_nodes, &LEVEL_26);
    prune(&mut temp_nodes, &PRUNE_26);
    run_level(&mut temp_nodes, &LEVEL_27);
    run_level(&mut temp_nodes, &LEVEL_28);
    prune(&mut temp_nodes, &PRUNE_28);
    run_level(&mut temp_nodes, &LEVEL_29);
    prune(&mut temp_nodes, &PRUNE_29);
    run_level(&mut temp_nodes, &LEVEL_30);
    prune(&mut temp_nodes, &PRUNE_30);
    run_level(&mut temp_nodes, &LEVEL_31);
    run_level(&mut temp_nodes, &LEVEL_32);
    prune(&mut temp_nodes, &PRUNE_32);
    run_level(&mut temp_nodes, &LEVEL_33);
    prune(&mut temp_nodes, &PRUNE_33);
    run_level(&mut temp_nodes, &LEVEL_34);
    prune(&mut temp_nodes, &PRUNE_34);
    run_level(&mut temp_nodes, &LEVEL_35);
    run_level(&mut temp_nodes, &LEVEL_36);
    prune(&mut temp_nodes, &PRUNE_36);
    run_level(&mut temp_nodes, &LEVEL_37);
    prune(&mut temp_nodes, &PRUNE_37);
    run_level(&mut temp_nodes, &LEVEL_38);
    prune(&mut temp_nodes, &PRUNE_38);
    run_level(&mut temp_nodes, &LEVEL_39);
    run_level(&mut temp_nodes, &LEVEL_40);
    prune(&mut temp_nodes, &PRUNE_40);
    run_level(&mut temp_nodes, &LEVEL_41);
    prune(&mut temp_nodes, &PRUNE_41);
    run_level(&mut temp_nodes, &LEVEL_42);
    prune(&mut temp_nodes, &PRUNE_42);
    run_level(&mut temp_nodes, &LEVEL_43);
    run_level(&mut temp_nodes, &LEVEL_44);
    prune(&mut temp_nodes, &PRUNE_44);
    run_level(&mut temp_nodes, &LEVEL_45);
    prune(&mut temp_nodes, &PRUNE_45);
    run_level(&mut temp_nodes, &LEVEL_46);
    prune(&mut temp_nodes, &PRUNE_46);
    run_level(&mut temp_nodes, &LEVEL_47);
    run_level(&mut temp_nodes, &LEVEL_48);
    prune(&mut temp_nodes, &PRUNE_48);
    run_level(&mut temp_nodes, &LEVEL_49);
    prune(&mut temp_nodes, &PRUNE_49);
    run_level(&mut temp_nodes, &LEVEL_50);
    prune(&mut temp_nodes, &PRUNE_50);
    run_level(&mut temp_nodes, &LEVEL_51);
    run_level(&mut temp_nodes, &LEVEL_52);
    prune(&mut temp_nodes, &PRUNE_52);
    run_level(&mut temp_nodes, &LEVEL_53);
    prune(&mut temp_nodes, &PRUNE_53);
    run_level(&mut temp_nodes, &LEVEL_54);
    prune(&mut temp_nodes, &PRUNE_54);
    run_level(&mut temp_nodes, &LEVEL_55);
    run_level(&mut temp_nodes, &LEVEL_56);
    prune(&mut temp_nodes, &PRUNE_56);
    run_level(&mut temp_nodes, &LEVEL_57);
    run_level(&mut temp_nodes, &LEVEL_58);
    prune(&mut temp_nodes, &PRUNE_58);
    run_level(&mut temp_nodes, &LEVEL_59);
    run_level(&mut temp_nodes, &LEVEL_60);
    prune(&mut temp_nodes, &PRUNE_60);
    run_level(&mut temp_nodes, &LEVEL_61);
    prune(&mut temp_nodes, &PRUNE_61);

            

                out.into_iter().map(|c| c.unwrap()).collect()
            }),
        )
        .unwrap()
}

