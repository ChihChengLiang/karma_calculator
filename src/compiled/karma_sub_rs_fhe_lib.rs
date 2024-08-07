
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
    ((27, false, INV), &[Arg(0, 0)]),
];

static LEVEL_1: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((172, false, INV), &[Arg(1, 1)]),
    ((39, false, NAND2), &[Arg(1, 0), Tv(27)]),
    ((59, false, XNOR2), &[Arg(1, 1), Arg(0, 1)]),
];

static LEVEL_2: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((58, false, NAND2), &[Tv(172), Arg(0, 1)]),
    ((60, false, NAND2), &[Tv(39), Tv(59)]),
];

static LEVEL_3: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((173, false, INV), &[Arg(1, 2)]),
    ((61, false, NAND2), &[Tv(58), Tv(60)]),
    ((62, false, XNOR2), &[Arg(1, 2), Arg(0, 2)]),
];

static LEVEL_4: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((57, false, NAND2), &[Tv(173), Arg(0, 2)]),
    ((63, false, NAND2), &[Tv(61), Tv(62)]),
];

static LEVEL_5: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((174, false, INV), &[Arg(1, 3)]),
    ((64, false, NAND2), &[Tv(57), Tv(63)]),
    ((65, false, XNOR2), &[Arg(1, 3), Arg(0, 3)]),
];

static LEVEL_6: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((56, false, NAND2), &[Tv(174), Arg(0, 3)]),
    ((66, false, NAND2), &[Tv(64), Tv(65)]),
];

static LEVEL_7: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((0, false, INV), &[Arg(1, 4)]),
    ((67, false, NAND2), &[Tv(56), Tv(66)]),
    ((68, false, XNOR2), &[Arg(1, 4), Arg(0, 4)]),
];

static LEVEL_8: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((55, false, NAND2), &[Tv(0), Arg(0, 4)]),
    ((69, false, NAND2), &[Tv(67), Tv(68)]),
];

static LEVEL_9: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((1, false, INV), &[Arg(1, 5)]),
    ((70, false, NAND2), &[Tv(55), Tv(69)]),
    ((71, false, XNOR2), &[Arg(1, 5), Arg(0, 5)]),
];

static LEVEL_10: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((54, false, NAND2), &[Tv(1), Arg(0, 5)]),
    ((72, false, NAND2), &[Tv(70), Tv(71)]),
];

static LEVEL_11: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((2, false, INV), &[Arg(1, 6)]),
    ((53, false, XNOR2), &[Arg(1, 6), Arg(0, 6)]),
    ((73, false, NAND2), &[Tv(54), Tv(72)]),
];

static LEVEL_12: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((28, false, INV), &[Arg(0, 7)]),
    ((52, false, NAND2), &[Tv(2), Arg(0, 6)]),
    ((74, false, NAND2), &[Tv(53), Tv(73)]),
];

static LEVEL_13: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((3, false, INV), &[Arg(1, 7)]),
    ((51, false, NAND2), &[Arg(1, 7), Tv(28)]),
    ((75, false, NAND2), &[Tv(52), Tv(74)]),
];

static LEVEL_14: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((50, false, NAND2), &[Tv(3), Arg(0, 7)]),
    ((76, false, NAND2), &[Tv(51), Tv(75)]),
];

static LEVEL_15: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((4, false, INV), &[Arg(1, 8)]),
    ((49, false, XNOR2), &[Arg(1, 8), Arg(0, 8)]),
    ((77, false, NAND2), &[Tv(50), Tv(76)]),
];

static LEVEL_16: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((29, false, INV), &[Arg(0, 9)]),
    ((48, false, NAND2), &[Tv(4), Arg(0, 8)]),
    ((78, false, NAND2), &[Tv(49), Tv(77)]),
];

static LEVEL_17: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((5, false, INV), &[Arg(1, 9)]),
    ((47, false, NAND2), &[Arg(1, 9), Tv(29)]),
    ((79, false, NAND2), &[Tv(48), Tv(78)]),
];

static LEVEL_18: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((46, false, NAND2), &[Tv(5), Arg(0, 9)]),
    ((80, false, NAND2), &[Tv(47), Tv(79)]),
];

static LEVEL_19: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((6, false, INV), &[Arg(1, 10)]),
    ((45, false, XNOR2), &[Arg(1, 10), Arg(0, 10)]),
    ((81, false, NAND2), &[Tv(46), Tv(80)]),
];

static LEVEL_20: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((30, false, INV), &[Arg(0, 11)]),
    ((44, false, NAND2), &[Tv(6), Arg(0, 10)]),
    ((82, false, NAND2), &[Tv(45), Tv(81)]),
];

static LEVEL_21: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((7, false, INV), &[Arg(1, 11)]),
    ((43, false, NAND2), &[Arg(1, 11), Tv(30)]),
    ((83, false, NAND2), &[Tv(44), Tv(82)]),
];

static LEVEL_22: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((42, false, NAND2), &[Tv(7), Arg(0, 11)]),
    ((84, false, NAND2), &[Tv(43), Tv(83)]),
];

static LEVEL_23: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((8, false, INV), &[Arg(1, 12)]),
    ((41, false, XNOR2), &[Arg(1, 12), Arg(0, 12)]),
    ((85, false, NAND2), &[Tv(42), Tv(84)]),
];

static LEVEL_24: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((9, false, INV), &[Arg(1, 13)]),
    ((40, false, NAND2), &[Tv(8), Arg(0, 12)]),
    ((86, false, NAND2), &[Tv(41), Tv(85)]),
];

static LEVEL_25: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((31, false, INV), &[Arg(0, 13)]),
    ((87, false, AND2), &[Tv(40), Tv(86)]),
    ((88, false, NAND2), &[Tv(9), Arg(0, 13)]),
];

static LEVEL_26: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((89, false, NAND2), &[Arg(1, 13), Tv(31)]),
    ((93, false, NAND2), &[Tv(87), Tv(88)]),
];

static LEVEL_27: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((10, false, INV), &[Arg(1, 14)]),
    ((92, false, XNOR2), &[Arg(1, 14), Arg(0, 14)]),
    ((94, false, AND2), &[Tv(89), Tv(93)]),
];

static LEVEL_28: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((11, false, INV), &[Arg(1, 15)]),
    ((91, false, NAND2), &[Tv(10), Arg(0, 14)]),
    ((95, false, NAND2), &[Tv(92), Tv(94)]),
];

static LEVEL_29: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((32, false, INV), &[Arg(0, 15)]),
    ((96, false, AND2), &[Tv(91), Tv(95)]),
    ((97, false, NAND2), &[Tv(11), Arg(0, 15)]),
];

static LEVEL_30: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((98, false, NAND2), &[Arg(1, 15), Tv(32)]),
    ((102, false, NAND2), &[Tv(96), Tv(97)]),
];

static LEVEL_31: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((12, false, INV), &[Arg(1, 16)]),
    ((101, false, XNOR2), &[Arg(1, 16), Arg(0, 16)]),
    ((103, false, AND2), &[Tv(98), Tv(102)]),
];

static LEVEL_32: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((13, false, INV), &[Arg(1, 17)]),
    ((100, false, NAND2), &[Tv(12), Arg(0, 16)]),
    ((104, false, NAND2), &[Tv(101), Tv(103)]),
];

static LEVEL_33: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((33, false, INV), &[Arg(0, 17)]),
    ((105, false, AND2), &[Tv(100), Tv(104)]),
    ((106, false, NAND2), &[Tv(13), Arg(0, 17)]),
];

static LEVEL_34: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((107, false, NAND2), &[Arg(1, 17), Tv(33)]),
    ((111, false, NAND2), &[Tv(105), Tv(106)]),
];

static LEVEL_35: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((14, false, INV), &[Arg(1, 18)]),
    ((110, false, XNOR2), &[Arg(1, 18), Arg(0, 18)]),
    ((112, false, AND2), &[Tv(107), Tv(111)]),
];

static LEVEL_36: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((15, false, INV), &[Arg(1, 19)]),
    ((109, false, NAND2), &[Tv(14), Arg(0, 18)]),
    ((113, false, NAND2), &[Tv(110), Tv(112)]),
];

static LEVEL_37: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((34, false, INV), &[Arg(0, 19)]),
    ((114, false, AND2), &[Tv(109), Tv(113)]),
    ((115, false, NAND2), &[Tv(15), Arg(0, 19)]),
];

static LEVEL_38: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((116, false, NAND2), &[Arg(1, 19), Tv(34)]),
    ((120, false, NAND2), &[Tv(114), Tv(115)]),
];

static LEVEL_39: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((16, false, INV), &[Arg(1, 20)]),
    ((119, false, XNOR2), &[Arg(1, 20), Arg(0, 20)]),
    ((121, false, AND2), &[Tv(116), Tv(120)]),
];

static LEVEL_40: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((17, false, INV), &[Arg(1, 21)]),
    ((118, false, NAND2), &[Tv(16), Arg(0, 20)]),
    ((122, false, NAND2), &[Tv(119), Tv(121)]),
];

static LEVEL_41: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((35, false, INV), &[Arg(0, 21)]),
    ((123, false, AND2), &[Tv(118), Tv(122)]),
    ((124, false, NAND2), &[Tv(17), Arg(0, 21)]),
];

static LEVEL_42: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((125, false, NAND2), &[Arg(1, 21), Tv(35)]),
    ((129, false, NAND2), &[Tv(123), Tv(124)]),
];

static LEVEL_43: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((18, false, INV), &[Arg(1, 22)]),
    ((128, false, XNOR2), &[Arg(1, 22), Arg(0, 22)]),
    ((130, false, AND2), &[Tv(125), Tv(129)]),
];

static LEVEL_44: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((19, false, INV), &[Arg(1, 23)]),
    ((127, false, NAND2), &[Tv(18), Arg(0, 22)]),
    ((131, false, NAND2), &[Tv(128), Tv(130)]),
];

static LEVEL_45: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((36, false, INV), &[Arg(0, 23)]),
    ((132, false, AND2), &[Tv(127), Tv(131)]),
    ((133, false, NAND2), &[Tv(19), Arg(0, 23)]),
];

static LEVEL_46: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((134, false, NAND2), &[Arg(1, 23), Tv(36)]),
    ((138, false, NAND2), &[Tv(132), Tv(133)]),
];

static LEVEL_47: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((20, false, INV), &[Arg(1, 24)]),
    ((137, false, XNOR2), &[Arg(1, 24), Arg(0, 24)]),
    ((139, false, AND2), &[Tv(134), Tv(138)]),
];

static LEVEL_48: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((21, false, INV), &[Arg(1, 25)]),
    ((136, false, NAND2), &[Tv(20), Arg(0, 24)]),
    ((140, false, NAND2), &[Tv(137), Tv(139)]),
];

static LEVEL_49: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((37, false, INV), &[Arg(0, 25)]),
    ((141, false, AND2), &[Tv(136), Tv(140)]),
    ((142, false, NAND2), &[Tv(21), Arg(0, 25)]),
];

static LEVEL_50: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((143, false, NAND2), &[Arg(1, 25), Tv(37)]),
    ((147, false, NAND2), &[Tv(141), Tv(142)]),
];

static LEVEL_51: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((22, false, INV), &[Arg(1, 26)]),
    ((146, false, XNOR2), &[Arg(1, 26), Arg(0, 26)]),
    ((148, false, AND2), &[Tv(143), Tv(147)]),
];

static LEVEL_52: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((23, false, INV), &[Arg(1, 27)]),
    ((145, false, NAND2), &[Tv(22), Arg(0, 26)]),
    ((149, false, NAND2), &[Tv(146), Tv(148)]),
];

static LEVEL_53: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((38, false, INV), &[Arg(0, 27)]),
    ((150, false, AND2), &[Tv(145), Tv(149)]),
    ((151, false, NAND2), &[Tv(23), Arg(0, 27)]),
];

static LEVEL_54: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((152, false, NAND2), &[Arg(1, 27), Tv(38)]),
    ((156, false, NAND2), &[Tv(150), Tv(151)]),
];

static LEVEL_55: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((24, false, INV), &[Arg(1, 28)]),
    ((155, false, XNOR2), &[Arg(1, 28), Arg(0, 28)]),
    ((157, false, AND2), &[Tv(152), Tv(156)]),
];

static LEVEL_56: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((154, false, NAND2), &[Tv(24), Arg(0, 28)]),
    ((158, false, NAND2), &[Tv(155), Tv(157)]),
];

static LEVEL_57: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((25, false, INV), &[Arg(1, 29)]),
    ((159, false, NAND2), &[Tv(154), Tv(158)]),
    ((161, false, XNOR2), &[Arg(1, 29), Arg(0, 29)]),
];

static LEVEL_58: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((160, false, NAND2), &[Tv(25), Arg(0, 29)]),
    ((162, false, NAND2), &[Tv(159), Tv(161)]),
];

static LEVEL_59: [((usize, bool, CellType), &[GateInput]); 3] = [
    ((26, false, INV), &[Arg(1, 30)]),
    ((163, false, NAND2), &[Tv(160), Tv(162)]),
    ((165, false, XNOR2), &[Arg(1, 30), Arg(0, 30)]),
];

static LEVEL_60: [((usize, bool, CellType), &[GateInput]); 2] = [
    ((164, false, NAND2), &[Tv(26), Arg(0, 30)]),
    ((166, false, NAND2), &[Tv(163), Tv(165)]),
];

static LEVEL_61: [((usize, bool, CellType), &[GateInput]); 13] = [
    ((90, false, XNOR2), &[Arg(1, 13), Arg(0, 13)]),
    ((99, false, XNOR2), &[Arg(1, 15), Arg(0, 15)]),
    ((108, false, XNOR2), &[Arg(1, 17), Arg(0, 17)]),
    ((117, false, XNOR2), &[Arg(1, 19), Arg(0, 19)]),
    ((126, false, XNOR2), &[Arg(1, 21), Arg(0, 21)]),
    ((135, false, XNOR2), &[Arg(1, 23), Arg(0, 23)]),
    ((144, false, XNOR2), &[Arg(1, 25), Arg(0, 25)]),
    ((153, false, XNOR2), &[Arg(1, 27), Arg(0, 27)]),
    ((167, false, NAND2), &[Tv(164), Tv(166)]),
    ((168, false, XOR2), &[Arg(1, 31), Arg(0, 31)]),
    ((169, false, XOR2), &[Arg(1, 7), Arg(0, 7)]),
    ((170, false, XOR2), &[Arg(1, 9), Arg(0, 9)]),
    ((171, false, XOR2), &[Arg(1, 11), Arg(0, 11)]),
];

static LEVEL_62: [((usize, bool, CellType), &[GateInput]); 32] = [
    ((0, true, XOR2), &[Arg(1, 0), Arg(0, 0)]),
    ((13, true, XNOR2), &[Tv(87), Tv(90)]),
    ((14, true, XOR2), &[Tv(92), Tv(94)]),
    ((15, true, XNOR2), &[Tv(96), Tv(99)]),
    ((16, true, XOR2), &[Tv(101), Tv(103)]),
    ((17, true, XNOR2), &[Tv(105), Tv(108)]),
    ((18, true, XOR2), &[Tv(110), Tv(112)]),
    ((19, true, XNOR2), &[Tv(114), Tv(117)]),
    ((20, true, XOR2), &[Tv(119), Tv(121)]),
    ((21, true, XNOR2), &[Tv(123), Tv(126)]),
    ((22, true, XOR2), &[Tv(128), Tv(130)]),
    ((23, true, XNOR2), &[Tv(132), Tv(135)]),
    ((24, true, XOR2), &[Tv(137), Tv(139)]),
    ((25, true, XNOR2), &[Tv(141), Tv(144)]),
    ((26, true, XOR2), &[Tv(146), Tv(148)]),
    ((27, true, XNOR2), &[Tv(150), Tv(153)]),
    ((28, true, XOR2), &[Tv(155), Tv(157)]),
    ((29, true, XOR2), &[Tv(159), Tv(161)]),
    ((30, true, XOR2), &[Tv(163), Tv(165)]),
    ((31, true, XNOR2), &[Tv(167), Tv(168)]),
    ((1, true, XOR2), &[Tv(39), Tv(59)]),
    ((2, true, XOR2), &[Tv(61), Tv(62)]),
    ((3, true, XOR2), &[Tv(64), Tv(65)]),
    ((4, true, XOR2), &[Tv(67), Tv(68)]),
    ((5, true, XOR2), &[Tv(70), Tv(71)]),
    ((6, true, XOR2), &[Tv(53), Tv(73)]),
    ((7, true, XNOR2), &[Tv(75), Tv(169)]),
    ((8, true, XOR2), &[Tv(49), Tv(77)]),
    ((9, true, XNOR2), &[Tv(79), Tv(170)]),
    ((10, true, XOR2), &[Tv(45), Tv(81)]),
    ((11, true, XNOR2), &[Tv(83), Tv(171)]),
    ((12, true, XOR2), &[Tv(41), Tv(85)]),
];

static PRUNE_36: [usize; 1] = [
  14,
];

static PRUNE_42: [usize; 2] = [
  124,
  35,
];

static PRUNE_11: [usize; 2] = [
  54,
  72,
];

static PRUNE_35: [usize; 2] = [
  107,
  111,
];

static PRUNE_4: [usize; 1] = [
  173,
];

static PRUNE_28: [usize; 1] = [
  10,
];

static PRUNE_59: [usize; 2] = [
  162,
  160,
];

static PRUNE_21: [usize; 3] = [
  82,
  44,
  30,
];

static PRUNE_52: [usize; 1] = [
  22,
];

static PRUNE_8: [usize; 1] = [
  0,
];

static PRUNE_32: [usize; 1] = [
  12,
];

static PRUNE_1: [usize; 1] = [
  27,
];

static PRUNE_56: [usize; 1] = [
  24,
];

static PRUNE_25: [usize; 3] = [
  9,
  40,
  86,
];

static PRUNE_49: [usize; 3] = [
  136,
  21,
  140,
];

static PRUNE_18: [usize; 2] = [
  47,
  5,
];

static PRUNE_17: [usize; 3] = [
  48,
  29,
  78,
];

static PRUNE_48: [usize; 1] = [
  20,
];

static PRUNE_41: [usize; 3] = [
  118,
  17,
  122,
];

static PRUNE_10: [usize; 1] = [
  1,
];

static PRUNE_34: [usize; 2] = [
  33,
  106,
];

static PRUNE_3: [usize; 2] = [
  60,
  58,
];

static PRUNE_58: [usize; 1] = [
  25,
];

static PRUNE_27: [usize; 2] = [
  93,
  89,
];

static PRUNE_14: [usize; 2] = [
  3,
  51,
];

static PRUNE_45: [usize; 3] = [
  127,
  131,
  19,
];

static PRUNE_7: [usize; 2] = [
  56,
  66,
];

static PRUNE_38: [usize; 2] = [
  34,
  115,
];

static PRUNE_31: [usize; 2] = [
  102,
  98,
];

static PRUNE_62: [usize; 62] = [
  121,
  90,
  169,
  59,
  87,
  73,
  135,
  79,
  144,
  65,
  96,
  155,
  45,
  110,
  62,
  141,
  85,
  71,
  161,
  68,
  130,
  99,
  153,
  139,
  77,
  108,
  170,
  150,
  119,
  167,
  105,
  128,
  159,
  83,
  114,
  94,
  49,
  41,
  103,
  165,
  148,
  117,
  171,
  157,
  64,
  126,
  75,
  137,
  168,
  61,
  92,
  123,
  146,
  53,
  132,
  39,
  70,
  101,
  163,
  112,
  81,
  67,
];

static PRUNE_24: [usize; 1] = [
  8,
];

static PRUNE_55: [usize; 2] = [
  152,
  156,
];

static PRUNE_54: [usize; 2] = [
  151,
  38,
];

static PRUNE_23: [usize; 2] = [
  42,
  84,
];

static PRUNE_47: [usize; 2] = [
  138,
  134,
];

static PRUNE_16: [usize; 1] = [
  4,
];

static PRUNE_9: [usize; 2] = [
  69,
  55,
];

static PRUNE_40: [usize; 1] = [
  16,
];

static PRUNE_2: [usize; 1] = [
  172,
];

static PRUNE_33: [usize; 3] = [
  104,
  100,
  13,
];

static PRUNE_51: [usize; 2] = [
  147,
  143,
];

static PRUNE_20: [usize; 1] = [
  6,
];

static PRUNE_44: [usize; 1] = [
  18,
];

static PRUNE_13: [usize; 3] = [
  28,
  74,
  52,
];

static PRUNE_37: [usize; 3] = [
  113,
  15,
  109,
];

static PRUNE_61: [usize; 2] = [
  166,
  164,
];

static PRUNE_6: [usize; 1] = [
  174,
];

static PRUNE_30: [usize; 2] = [
  97,
  32,
];

static PRUNE_29: [usize; 3] = [
  11,
  91,
  95,
];

static PRUNE_60: [usize; 1] = [
  26,
];

static PRUNE_53: [usize; 3] = [
  149,
  23,
  145,
];

static PRUNE_22: [usize; 2] = [
  43,
  7,
];

static PRUNE_15: [usize; 2] = [
  76,
  50,
];

static PRUNE_46: [usize; 2] = [
  133,
  36,
];

static PRUNE_39: [usize; 2] = [
  116,
  120,
];

static PRUNE_26: [usize; 2] = [
  31,
  88,
];

static PRUNE_57: [usize; 2] = [
  158,
  154,
];

static PRUNE_19: [usize; 2] = [
  46,
  80,
];

static PRUNE_50: [usize; 2] = [
  37,
  142,
];

static PRUNE_12: [usize; 1] = [
  2,
];

static PRUNE_43: [usize; 2] = [
  125,
  129,
];

static PRUNE_5: [usize; 2] = [
  57,
  63,
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
    run_level(&mut temp_nodes, &LEVEL_31);
    prune(&mut temp_nodes, &PRUNE_31);
    run_level(&mut temp_nodes, &LEVEL_32);
    prune(&mut temp_nodes, &PRUNE_32);
    run_level(&mut temp_nodes, &LEVEL_33);
    prune(&mut temp_nodes, &PRUNE_33);
    run_level(&mut temp_nodes, &LEVEL_34);
    prune(&mut temp_nodes, &PRUNE_34);
    run_level(&mut temp_nodes, &LEVEL_35);
    prune(&mut temp_nodes, &PRUNE_35);
    run_level(&mut temp_nodes, &LEVEL_36);
    prune(&mut temp_nodes, &PRUNE_36);
    run_level(&mut temp_nodes, &LEVEL_37);
    prune(&mut temp_nodes, &PRUNE_37);
    run_level(&mut temp_nodes, &LEVEL_38);
    prune(&mut temp_nodes, &PRUNE_38);
    run_level(&mut temp_nodes, &LEVEL_39);
    prune(&mut temp_nodes, &PRUNE_39);
    run_level(&mut temp_nodes, &LEVEL_40);
    prune(&mut temp_nodes, &PRUNE_40);
    run_level(&mut temp_nodes, &LEVEL_41);
    prune(&mut temp_nodes, &PRUNE_41);
    run_level(&mut temp_nodes, &LEVEL_42);
    prune(&mut temp_nodes, &PRUNE_42);
    run_level(&mut temp_nodes, &LEVEL_43);
    prune(&mut temp_nodes, &PRUNE_43);
    run_level(&mut temp_nodes, &LEVEL_44);
    prune(&mut temp_nodes, &PRUNE_44);
    run_level(&mut temp_nodes, &LEVEL_45);
    prune(&mut temp_nodes, &PRUNE_45);
    run_level(&mut temp_nodes, &LEVEL_46);
    prune(&mut temp_nodes, &PRUNE_46);
    run_level(&mut temp_nodes, &LEVEL_47);
    prune(&mut temp_nodes, &PRUNE_47);
    run_level(&mut temp_nodes, &LEVEL_48);
    prune(&mut temp_nodes, &PRUNE_48);
    run_level(&mut temp_nodes, &LEVEL_49);
    prune(&mut temp_nodes, &PRUNE_49);
    run_level(&mut temp_nodes, &LEVEL_50);
    prune(&mut temp_nodes, &PRUNE_50);
    run_level(&mut temp_nodes, &LEVEL_51);
    prune(&mut temp_nodes, &PRUNE_51);
    run_level(&mut temp_nodes, &LEVEL_52);
    prune(&mut temp_nodes, &PRUNE_52);
    run_level(&mut temp_nodes, &LEVEL_53);
    prune(&mut temp_nodes, &PRUNE_53);
    run_level(&mut temp_nodes, &LEVEL_54);
    prune(&mut temp_nodes, &PRUNE_54);
    run_level(&mut temp_nodes, &LEVEL_55);
    prune(&mut temp_nodes, &PRUNE_55);
    run_level(&mut temp_nodes, &LEVEL_56);
    prune(&mut temp_nodes, &PRUNE_56);
    run_level(&mut temp_nodes, &LEVEL_57);
    prune(&mut temp_nodes, &PRUNE_57);
    run_level(&mut temp_nodes, &LEVEL_58);
    prune(&mut temp_nodes, &PRUNE_58);
    run_level(&mut temp_nodes, &LEVEL_59);
    prune(&mut temp_nodes, &PRUNE_59);
    run_level(&mut temp_nodes, &LEVEL_60);
    prune(&mut temp_nodes, &PRUNE_60);
    run_level(&mut temp_nodes, &LEVEL_61);
    prune(&mut temp_nodes, &PRUNE_61);
    run_level(&mut temp_nodes, &LEVEL_62);
    prune(&mut temp_nodes, &PRUNE_62);

            

                out.into_iter().map(|c| c.unwrap()).collect()
            }),
        )
        .unwrap()
}

