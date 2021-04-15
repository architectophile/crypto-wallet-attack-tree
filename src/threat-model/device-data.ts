import {
  DeviceInfo,
  DeviceType,
  ImpactedNodes,
  Node,
  NodeType,
  RemovedNodes,
} from "./common";
import { calculateCvssBaseMtrics, CVSS_METRIC } from "./cvss";
import { attacks } from "./node-data";

export enum PRODUCT_ID {
  LEDGER_NANO_S = 0,
  TREZOR_ONE = 1,
  BREAD_WALLET = 2,
  TRUST_WALLET = 3,
  COPAY_WALLET = 4,
  ELECTRUM_WALLET = 5,
}
export enum CHECKLIST_DOMAIN {
  COMMON,
  EMBEDDED_SYSTEM,
  MOBILE,
  PC,
}

export enum CHECKLIST_CATEGORY {
  AUTHENTICATION,
  OUTPUT,
  INPUT,
  COPY,
  KEY_GENERATION,
  KEY_MANAGEMENT,
  TRANSACTION,
  APPLICATION,
  NETWORK,
  RECOVERY,
  PRIVACY,
  FIRMWARE,
  DEBUGGER,
  COMMUNICATION,
  AUTHORIZATION,
  PRIVILEGE_ESCALATION,
}

export const embeddedRemovedNodes: RemovedNodes = {
  goals: {},
  subgoals: {},
  branchnodes: {
    "2": 1,
    "5": 1,
    "9": 1,
    "12": 1,
    "13": 1,
    "18": 1,
    "22": 1,
    "32": 1,
    "35": 1,
    "53": 1,
    "70": 1,
    "75": 1,
    "78": 1,
  },
  attacks: {
    "40": 1,
    "50": 1,
    "78": 1,
    "132": 1,
    "149": 1,
    "154": 1,
    "198": 1,
    "202": 1,
    "204": 1,
    "216": 1,
    "229": 1,
    "260": 1,
    "264": 1,
    "312": 1,
  },
};

export const mobileRemovedNodes: RemovedNodes = {
  goals: {},
  subgoals: {},
  branchnodes: {
    "27": 1,
    "47": 1,
    "62": 1,
    "109": 1,
  },
  attacks: {
    "30": 1,
    "38": 1,
    "82": 1,
    "153": 1,
    "207": 1,
    "268": 1,
  },
};

export const pcRemovedNodes: RemovedNodes = {
  goals: {},
  subgoals: {},
  branchnodes: {
    "27": 1,
    "47": 1,
    "62": 1,
    "109": 1,
  },
  attacks: {
    "30": 1,
    "38": 1,
    "40": 1,
    "50": 1,
    "66": 1,
    "82": 1,
    "132": 1,
    "153": 1,
    "154": 1,
    "204": 1,
    "207": 1,
    "229": 1,
    "268": 1,
  },
};

export interface Mitigation {
  type: NodeType;
  index: number;
  metrics: CVSS_METRIC[];
}

export interface Removal {
  type: NodeType;
  index: number;
  isNegative: boolean;
}

export interface CheckItem {
  domain: CHECKLIST_DOMAIN;
  category: CHECKLIST_CATEGORY;
  name: string;
  mitigations: Mitigation[] | null;
  removals: Removal[] | null;
  checkResults: number[]; //indices: ledger=0, trezor=1, bread=2, trust=3, copay=4, electrum=5
}

const secreqChecklistResults: CheckItem[] = [
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.AUTHENTICATION,
    name: "a. Does the wallet hide the PIN or password on the screen?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 24,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 147,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 200,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 262,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 310,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [0, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.AUTHENTICATION,
    name:
      "b. Does the wallet get disabled after a certain amount of consecutive unsuccessful authentication attempts?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 19,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 142,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 195,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 257,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 305,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [1, 1, 0, 1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.AUTHENTICATION,
    name:
      "c. Does the wallet get locked if it is not used for a certain period of time?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 23,
        metrics: [CVSS_METRIC.AC],
      },    
      {
        type: NodeType.ATTACK_VECTOR,
        index: 146,
        metrics: [CVSS_METRIC.AC],
      },    
      {
        type: NodeType.ATTACK_VECTOR,
        index: 199,
        metrics: [CVSS_METRIC.AC],
      },    
      {
        type: NodeType.ATTACK_VECTOR,
        index: 261,
        metrics: [CVSS_METRIC.AC],
      },    
      {
        type: NodeType.ATTACK_VECTOR,
        index: 309,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [1, -1, -1, 1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.AUTHENTICATION,
    name:
      "d. Can passphrase be added to the recovery phrase to create a hidden wallet?",
    mitigations: null,
    removals: [
      {
        type: NodeType.BRANCH_NODE,
        index: 11,
        isNegative: true,
      },
      {
        type: NodeType.BRANCH_NODE,
        index: 55,
        isNegative: true,
      },
      {
        type: NodeType.BRANCH_NODE,
        index: 94,
        isNegative: true,
      },
    ],
    checkResults: [1, 1, -1, -1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.AUTHENTICATION,
    name:
      "e. Is there any protection mechanism for authentication credentials (e.g., encryption, hash, or secure element)?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 21,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 144,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 197,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 259,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 307,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.AUTHENTICATION,
    name:
      "f. Is there any defense mechanism for physical attacks (e.g., fault injection) on the user authentication process?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 25,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 29,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 39,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 152,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 201,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 263,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 267,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 311,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, -1, -1, -1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.OUTPUT,
    name:
      "a. Is there a mechanism to prevent screen capture when a private key or recovery phrase is displayed?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 10,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 26,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 35,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 149,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 202,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 264,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 278,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 312,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 322,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
    ],
    removals: null,
    checkResults: [1, 1, -1, 1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.OUTPUT,
    name:
      "b.  Does the wallet deliver a warning message about the risk of exposing a private key or recovery phrase before they are displayed?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 11,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 27,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 150,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [0, 1, -1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.OUTPUT,
    name:
      "c. Is user authentication required before displaying a private key or recovery phrase at the request of a user?",
    mitigations: null,
    removals: [
      {
        type: NodeType.BRANCH_NODE,
        index: 10,
        isNegative: true,
      },
    ],
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.INPUT,
    name:
      "a. Is there a defense mechanism for keylogging attacks when a private key or recovery phrase is entered by a user?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 5,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 26,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 37,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 149,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 202,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 264,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 273,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 312,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 317,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC],
      },
    ],
    removals: null,
    checkResults: [1, 1, -1, -1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.COPY,
    name:
      "a. Is it forbidden to copy a private key or recovery phrase to the clipboard?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 36,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 49,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.PR],
      },
    ],
    removals: null,
    checkResults: [1, 1, -1, 1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.KEY_GENERATION,
    name:
      "a. Is a proven random number generator used to generate a seed or a private key?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 96,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.KEY_GENERATION,
    name: "b. Is more than 112-bit entropy used to generate a master seed?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 96,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.KEY_MANAGEMENT,
    name:
      "a. Is an encryption key that provides more than 112 bits of security length used to encrypt a private key or recovery phrase?",
    mitigations: null,
    removals: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 43,
        isNegative: true,
      },
    ],
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.KEY_MANAGEMENT,
    name:
      "b. Is there an access control mechanism for the encrypted private key or recovery phrase?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 38,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 39,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.KEY_MANAGEMENT,
    name:
      "c. Is there any defense mechanism for physical attacks (e.g., microprobing or reverse engineering)on the device?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 25,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 29,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 39,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 44,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 148,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 152,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 199,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 201,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 227,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 263,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 267,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 311,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, -1, -1, -1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.TRANSACTION,
    name:
      "a. Is the detail of a new transaction displayed and user confirmation is required before signing the transaction? ",
    mitigations: null,
    removals: [
      {
        type: NodeType.BRANCH_NODE,
        index: 41,
        isNegative: true,
      },
      {
        type: NodeType.BRANCH_NODE,
        index: 46,
        isNegative: true,
      },
    ],
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.TRANSACTION,
    name:
      "b. Is user authentication required before signing a new transaction?",
    mitigations: null,
    removals: [
      {
        type: NodeType.BRANCH_NODE,
        index: 54,
        isNegative: true,
      },
    ],
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.TRANSACTION,
    name:
      "c. Is a proven random number generator used to generate a signature?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 97,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 98,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.APPLICATION,
    name:
      "a. Is there any integrity verification mechanism for the wallet application or wallet manager?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 54,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 56,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 57,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 58,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 106,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 108,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 109,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 110,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 158,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 160,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 161,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 162,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.NETWORK,
    name:
      "a. Is data transmitted across networks through secure channels (e.g., HTTPS)?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 289,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 290,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 291,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 333,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 334,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 335,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.NETWORK,
    name:
      "b. Does the wallet device keep offline (air-gapped) when it is not used?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 1,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 2,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 5,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 6,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 7,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 10,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 26,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 31,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 32,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 35,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 36,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 37,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 45,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 46,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 49,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 83,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 84,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 87,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 99,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 100,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 103,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 149,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 183,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 184,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 187,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 202,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 208,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 209,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 212,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 233,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 234,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 237,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 264,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 312,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [1, 1, -1, -1, -1, -1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.RECOVERY,
    name:
      "a. Are there any instructions explaining the importance of backing up private keys or a recovery phrase?",
    mitigations: [
      {
        type: NodeType.SUB_GOAL,
        index: 4,
        metrics: [CVSS_METRIC.A],
      },
      {
        type: NodeType.SUB_GOAL,
        index: 5,
        metrics: [CVSS_METRIC.A],
      },
    ],
    removals: null,
    checkResults: [1, 1, 0, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.RECOVERY,
    name:
      "b. Is there a mechanism to check if the user has backed up a private key or recovery phrase?",
    mitigations: [
      {
        type: NodeType.SUB_GOAL,
        index: 4,
        metrics: [CVSS_METRIC.A],
      },
      {
        type: NodeType.SUB_GOAL,
        index: 5,
        metrics: [CVSS_METRIC.A],
      },
    ],
    removals: null,
    checkResults: [1, -1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.PRIVACY,
    name:
      "a. Is personally identifiable user information (e.g., name, email address, or phone number) is not entered or stored in the wallet?",
    mitigations: null,
    removals: [
      {
        type: NodeType.SUB_GOAL,
        index: 8,
        isNegative: false,
      },
    ],
    checkResults: [1, 1, 1, 1, 0, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.PRIVACY,
    name:
      "b. Is user authentication required before displaying an account address or balance?",
    mitigations: null,
    removals: [
      {
        type: NodeType.BRANCH_NODE,
        index: 92,
        isNegative: true,
      },
      {
        type: NodeType.BRANCH_NODE,
        index: 113,
        isNegative: true,
      },
    ],
    checkResults: [1, 1, 1, 1, -1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.EMBEDDED_SYSTEM,
    category: CHECKLIST_CATEGORY.OUTPUT,
    name:
      "a. Is there an output interface to display an account address or transaction information for user confirmation?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 104,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 118,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.EMBEDDED_SYSTEM,
    category: CHECKLIST_CATEGORY.FIRMWARE,
    name: "a. Is there any firmware integrity verification mechanism?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 70,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 72,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 73,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 74,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 120,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 122,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 123,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 124,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 171,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 173,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 174,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 175,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.EMBEDDED_SYSTEM,
    category: CHECKLIST_CATEGORY.DEBUGGER,
    name: "a. Are debugger pins removed or disabled (e.g., JTAG interface)?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 82,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 153,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 207,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 232,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 268,
        metrics: [CVSS_METRIC.AC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.EMBEDDED_SYSTEM,
    category: CHECKLIST_CATEGORY.COMMUNICATION,
    name:
      "a. Is there a secure communication mechanism between the host and the wallet device (e.g., secure channel)?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 296,
        metrics: [CVSS_METRIC.TC, CVSS_METRIC.EX, CVSS_METRIC.EQ],
      },
    ],
    removals: null,
    checkResults: [1, -1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.EMBEDDED_SYSTEM,
    category: CHECKLIST_CATEGORY.AUTHENTICATION,
    name:
      "a. Is there a mechanism for checking the authenticity of the wallet device that is connected to the host?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 71,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 121,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 172,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
    ],
    removals: null,
    checkResults: [1, -1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.EMBEDDED_SYSTEM,
    category: CHECKLIST_CATEGORY.AUTHORIZATION,
    name:
      "a. Is there an authorization mechanism for the wallet manager that is installed on the external host?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 55,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 107,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 159,
        metrics: [CVSS_METRIC.PR, CVSS_METRIC.EX],
      },
    ],
    removals: null,
    checkResults: [0, 0, 0, 0, 0, 0],
  },
  {
    domain: CHECKLIST_DOMAIN.MOBILE,
    category: CHECKLIST_CATEGORY.PRIVILEGE_ESCALATION,
    name: "a. Is there a mechanism to check if the device is rooted?",
    mitigations: null,
    removals: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 40,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 50,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 66,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 132,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 154,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 204,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 229,
        isNegative: true,
      },
    ],
    checkResults: [1, 1, 1, 1, 1, 1],
  },
];

const getRemovedNodesFromTable = (id: PRODUCT_ID): RemovedNodes => {
  const result: RemovedNodes = secreqChecklistResults.reduce(
    (acumm: RemovedNodes, current: CheckItem): RemovedNodes => {
      if (current.removals && current.removals.length) {
        const checkResult = current.checkResults[id];
        current.removals.forEach((removal: Removal) => {
          if (
            (removal.isNegative && checkResult === -1) ||
            (!removal.isNegative && checkResult === 1)
          ) {
            switch (removal.type) {
              case NodeType.ROOT_GOAL: {
                acumm.goals = Object.assign({}, acumm.goals, {
                  [removal.index]: 1,
                });
                break;
              }
              case NodeType.SUB_GOAL: {
                acumm.subgoals = Object.assign({}, acumm.subgoals, {
                  [removal.index]: 1,
                });
                break;
              }
              case NodeType.BRANCH_NODE: {
                acumm.branchnodes = Object.assign({}, acumm.branchnodes, {
                  [removal.index]: 1,
                });
                break;
              }
              case NodeType.ATTACK_VECTOR: {
                acumm.attacks = Object.assign({}, acumm.attacks, {
                  [removal.index]: 1,
                });
                break;
              }
            }
          }
        });
      }

      return acumm;
    },
    { goals: {}, subgoals: {}, branchnodes: {}, attacks: {} },
  );

  return result;
};

const getProductSpecificRemovedNodes = (id: PRODUCT_ID): RemovedNodes => {
  let removedNodes: RemovedNodes = {
    goals: {},
    subgoals: {},
    branchnodes: {},
    attacks: {},
  };

  switch (id) {
    case PRODUCT_ID.LEDGER_NANO_S: {
      removedNodes.goals = Object.assign({}, embeddedRemovedNodes.goals);
      removedNodes.subgoals = Object.assign({}, embeddedRemovedNodes.subgoals);
      removedNodes.branchnodes = Object.assign(
        {},
        embeddedRemovedNodes.branchnodes,
      );
      removedNodes.attacks = Object.assign({}, embeddedRemovedNodes.attacks);
      break;
    }
    case PRODUCT_ID.TREZOR_ONE: {
      removedNodes.goals = Object.assign({}, embeddedRemovedNodes.goals);
      removedNodes.subgoals = Object.assign({}, embeddedRemovedNodes.subgoals);
      removedNodes.branchnodes = Object.assign(
        {},
        embeddedRemovedNodes.branchnodes,
      );
      removedNodes.attacks = Object.assign({}, embeddedRemovedNodes.attacks);
      break;
    }
    case PRODUCT_ID.BREAD_WALLET: {
      removedNodes.goals = Object.assign({}, mobileRemovedNodes.goals);
      removedNodes.subgoals = Object.assign({}, mobileRemovedNodes.subgoals);
      removedNodes.branchnodes = Object.assign(
        {},
        mobileRemovedNodes.branchnodes,
      );
      removedNodes.attacks = Object.assign({}, mobileRemovedNodes.attacks);
      break;
    }
    case PRODUCT_ID.TRUST_WALLET: {
      removedNodes.goals = Object.assign({}, mobileRemovedNodes.goals);
      removedNodes.subgoals = Object.assign({}, mobileRemovedNodes.subgoals);
      removedNodes.branchnodes = Object.assign(
        {},
        mobileRemovedNodes.branchnodes,
      );
      removedNodes.attacks = Object.assign({}, mobileRemovedNodes.attacks);
      break;
    }
    case PRODUCT_ID.COPAY_WALLET: {
      removedNodes.goals = Object.assign({}, pcRemovedNodes.goals);
      removedNodes.subgoals = Object.assign({}, pcRemovedNodes.subgoals);
      removedNodes.branchnodes = Object.assign({}, pcRemovedNodes.branchnodes);
      removedNodes.attacks = Object.assign({}, pcRemovedNodes.attacks);
      break;
    }
    case PRODUCT_ID.ELECTRUM_WALLET: {
      removedNodes.goals = Object.assign({}, pcRemovedNodes.goals);
      removedNodes.subgoals = Object.assign({}, pcRemovedNodes.subgoals);
      removedNodes.branchnodes = Object.assign({}, pcRemovedNodes.branchnodes);
      removedNodes.attacks = Object.assign({}, pcRemovedNodes.attacks);
      break;
    }
    default:
      return removedNodes;
  }
  const checklistRemovedNodes: RemovedNodes = getRemovedNodesFromTable(id);
  removedNodes.goals = Object.assign(
    {},
    removedNodes.goals,
    checklistRemovedNodes.goals,
  );
  removedNodes.subgoals = Object.assign(
    {},
    removedNodes.subgoals,
    checklistRemovedNodes.subgoals,
  );
  removedNodes.branchnodes = Object.assign(
    {},
    removedNodes.branchnodes,
    checklistRemovedNodes.branchnodes,
  );
  removedNodes.attacks = Object.assign(
    {},
    removedNodes.attacks,
    checklistRemovedNodes.attacks,
  );

  return removedNodes;
};

const getImpactedNodesFromTable = (id: PRODUCT_ID): ImpactedNodes => {
  const result: ImpactedNodes = secreqChecklistResults.reduce(
    (acumm: ImpactedNodes, current: CheckItem): ImpactedNodes => {
      if (current.mitigations && current.mitigations.length) {
        const checkResult = current.checkResults[id];
        current.mitigations.forEach((mitigation: Mitigation) => {
          switch (mitigation.type) {
            case NodeType.ROOT_GOAL: {
              break;
            }
            case NodeType.SUB_GOAL: {
              break;
            }
            case NodeType.BRANCH_NODE: {
              break;
            }
            case NodeType.ATTACK_VECTOR: {
              if (acumm.attacks[mitigation.index]) {
                mitigation.metrics.forEach((metric) => {
                  acumm.attacks[mitigation.index][metric] += checkResult;
                });
              } else {
                const newScore = [0, 0, 0, 0, 0];
                acumm.attacks = Object.assign({}, acumm.attacks, {
                  [mitigation.index]: newScore,
                });
                mitigation.metrics.forEach((metric) => {
                  acumm.attacks[mitigation.index][metric] += checkResult;
                });
              }
              break;
            }
            default:
              break;
          }
        });
      }

      return acumm;
    },
    { goals: {}, subgoals: {}, branchnodes: {}, attacks: {} },
  );

  return result;
};

export const calculateDefaultCvssScore = (
  defaultScore: number[] | undefined,
): number => {
  return calculateCvssBaseMtrics(defaultScore as number[]);
};

export const calculateProductCvssScore = (
  defaultScore: number[],
  impactedScore: number[] | undefined,
): number => {
  const composedScore: number[] = defaultScore.slice() as number[];
  if (impactedScore) {
    // attack vector
    composedScore[CVSS_METRIC.AV] += impactedScore[CVSS_METRIC.AV];

    // access complexity
    composedScore[CVSS_METRIC.AC] += impactedScore[CVSS_METRIC.AC];

    // previlege required
    composedScore[CVSS_METRIC.PR] += impactedScore[CVSS_METRIC.PR];

    // user interaction
    composedScore[CVSS_METRIC.UI] += impactedScore[CVSS_METRIC.UI];

    // time complexity
    composedScore[CVSS_METRIC.TC] += impactedScore[CVSS_METRIC.TC];
  }
  return calculateCvssBaseMtrics(composedScore);
};

export const deviceLedger: DeviceInfo = {
  type: DeviceType.EMBEDDED_SYSTEM,
  name: "Ledger Nano S",
  productRemoved: getProductSpecificRemovedNodes(PRODUCT_ID.LEDGER_NANO_S),
  productImpacted: getImpactedNodesFromTable(PRODUCT_ID.LEDGER_NANO_S),
};

export const deviceTrezor: DeviceInfo = {
  type: DeviceType.EMBEDDED_SYSTEM,
  name: "Tezor One",
  productRemoved: getProductSpecificRemovedNodes(PRODUCT_ID.TREZOR_ONE),
  productImpacted: getImpactedNodesFromTable(PRODUCT_ID.TREZOR_ONE),
};

export const deviceBread: DeviceInfo = {
  type: DeviceType.MOBILE_ANDROID,
  name: "Bread Wallet",
  productRemoved: getProductSpecificRemovedNodes(PRODUCT_ID.BREAD_WALLET),
  productImpacted: getImpactedNodesFromTable(PRODUCT_ID.BREAD_WALLET),
};

export const deviceTrust: DeviceInfo = {
  type: DeviceType.MOBILE_ANDROID,
  name: "Trust Wallet",
  productRemoved: getProductSpecificRemovedNodes(PRODUCT_ID.TRUST_WALLET),
  productImpacted: getImpactedNodesFromTable(PRODUCT_ID.TRUST_WALLET),
};

export const deviceCopay: DeviceInfo = {
  type: DeviceType.PC,
  name: "Copay Wallet",
  productRemoved: getProductSpecificRemovedNodes(PRODUCT_ID.COPAY_WALLET),
  productImpacted: getImpactedNodesFromTable(PRODUCT_ID.COPAY_WALLET),
};

export const deviceElectrum: DeviceInfo = {
  type: DeviceType.PC,
  name: "Electrum Wallet",
  productRemoved: getProductSpecificRemovedNodes(PRODUCT_ID.ELECTRUM_WALLET),
  productImpacted: getImpactedNodesFromTable(PRODUCT_ID.ELECTRUM_WALLET),
};
