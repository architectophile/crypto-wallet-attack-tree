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
  branchnodes: {},
  attacks: {
    "22": 1,
    "26": 1,
    "52": 1,
    "65": 1,
    "87": 1,
    "95": 1,
    "121": 1,
    "125": 1,
  },
};

export const mobileRemovedNodes: RemovedNodes = {
  goals: {},
  subgoals: {},
  branchnodes: {
    "17": 1,
    "18": 1,
    "19": 1,
    "20": 1,
    "27": 1,
    "28": 1,
    "29": 1,
    "30": 1,
    "41": 1,
    "42": 1,
    "45": 1,
    "46": 1,
    "82": 1,
  },
  attacks: { "13": 1, "116": 1, "145": 1, "146": 1 },
};

export const pcRemovedNodes: RemovedNodes = {
  goals: {},
  subgoals: {},
  branchnodes: {
    "17": 1,
    "18": 1,
    "19": 1,
    "20": 1,
    "27": 1,
    "28": 1,
    "29": 1,
    "30": 1,
    "41": 1,
    "42": 1,
    "45": 1,
    "46": 1,
    "82": 1,
  },
  attacks: {
    "13": 1,
    "22": 1,
    "26": 1,
    "52": 1,
    "65": 1,
    "87": 1,
    "95": 1,
    "116": 1,
    "121": 1,
    "125": 1,
    "145": 1,
    "146": 1,
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
        index: 3,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 55,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 76,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 103,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 127,
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
        index: 5,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 57,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 78,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 105,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 129,
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
        index: 4,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 56,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 77,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 104,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 128,
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
        type: NodeType.ATTACK_VECTOR,
        index: 10,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 110,
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
    mitigations: null,
    removals: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 8,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 60,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 81,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 108,
        isNegative: true,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 132,
        isNegative: true,
      },
    ],
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
        index: 9,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 61,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 82,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 109,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 133,
        metrics: [CVSS_METRIC.AC],
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
        index: 12,
        metrics: [CVSS_METRIC.AC],
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
        index: 5,
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
        index: 1,
        metrics: [CVSS_METRIC.AC],
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
    mitigations: null,
    removals: [
      {
        type: NodeType.BRANCH_NODE,
        index: 13,
        isNegative: false,
      },
    ],
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
        index: 39,
        metrics: [CVSS_METRIC.TC],
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
        index: 39,
        metrics: [CVSS_METRIC.TC],
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
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 18,
        metrics: [CVSS_METRIC.TC],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.COMMON,
    category: CHECKLIST_CATEGORY.KEY_MANAGEMENT,
    name:
      "b. Is there an access control mechanism for the encrypted private key or recovery phrase?",
    mitigations: null,
    removals: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 17,
        isNegative: true,
      },
    ],
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
        index: 14,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 19,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 23,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 34,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 46,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 72,
        metrics: [CVSS_METRIC.AC],
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
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 53,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
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
        type: NodeType.ATTACK_VECTOR,
        index: 35,
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
        index: 37,
        metrics: [CVSS_METRIC.TC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 38,
        metrics: [CVSS_METRIC.TC],
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
        index: 29,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 30,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 41,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 42,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 70,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 71,
        metrics: [CVSS_METRIC.AC],
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
        index: 98,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 99,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 100,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 138,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 139,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 140,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 141,
        metrics: [CVSS_METRIC.AC],
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
        index: 12,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 15,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 22,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 26,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 27,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 49,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 52,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 65,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 87,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 90,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 95,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 97,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 111,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 112,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 113,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 114,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 121,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 125,
        metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 134,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 135,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 136,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
      // {
      //   type: NodeType.ATTACK_VECTOR,
      //   index: 138,
      //   metrics: [CVSS_METRIC.AV, CVSS_METRIC.AC],
      // },
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
        index: 63,
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
        index: 53,
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
        index: 32,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 33,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 44,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 45,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 67,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 68,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [1, 1, 1, 1, 1, 1],
  },
  {
    domain: CHECKLIST_DOMAIN.EMBEDDED_SYSTEM,
    category: CHECKLIST_CATEGORY.DEBUGGER,
    name: "a. Are debugger pins removed or disabled (e.g., JTAG interface)?",
    mitigations: null,
    removals: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 13,
        isNegative: false,
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 116,
        isNegative: false,
      },
    ],
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
        index: 137,
        metrics: [CVSS_METRIC.TC],
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
        index: 35,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 36,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 47,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 48,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 73,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 74,
        metrics: [CVSS_METRIC.AC],
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
        index: 53,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
    checkResults: [0, 0, 0, 0, 0, 0],
  },
  {
    domain: CHECKLIST_DOMAIN.MOBILE,
    category: CHECKLIST_CATEGORY.PRIVILEGE_ESCALATION,
    name: "a. Is there a mechanism to check if the device is rooted?",
    mitigations: [
      {
        type: NodeType.ATTACK_VECTOR,
        index: 22,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 26,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 52,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 65,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 87,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 95,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 121,
        metrics: [CVSS_METRIC.AC],
      },
      {
        type: NodeType.ATTACK_VECTOR,
        index: 125,
        metrics: [CVSS_METRIC.AC],
      },
    ],
    removals: null,
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
