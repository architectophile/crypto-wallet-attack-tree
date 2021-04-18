import {
  addNode,
  ICptWithoutParents,
  ICptWithParents,
  INetwork,
  INode,
} from "bayesjs";
import { RawNodeDatum } from "react-d3-tree/lib/types/common";
import {
  BNNodeDatum,
  DeviceInfo,
  NetworkContainer,
  NewNodeDatum,
  Node,
  NodeInfo,
  NodeInfoX,
  NodeType,
  OperatorAnd,
  OperatorOr,
} from "./common";
import { AC, AV, EQ, EX, PR, TC, UI } from "./cvss";
import {
  TH_ACCESS_PHYSICALLY,
  TH_ARP_SPOOFING,
  TH_BRUTE_FORCE,
  TH_BUFFER_OVERFLOW,
  TH_BYPASS_USER_CONFIRMATION,
  TH_COLD_BOOT,
  TH_CONNECT_DEBUGGER,
  TH_DECRYPT_DATA,
  TH_DNS_SPOOFING,
  TH_EVIL_MAID,
  TH_EXECUTE_CLIPBOARD_HIJACKING,
  TH_EXECUTE_KEY_LOGGING,
  TH_EXECUTE_NETWORK_PACKET_SNIFFING,
  TH_EXECUTE_RANSOMWARE,
  TH_EXECUTE_SCREEN_RECORDING,
  TH_EXECUTE_USB_PACKET_SNIFFING,
  TH_FACTORY_RESET_DISK_FORMATTING,
  TH_FAKE_BIOMETRICS,
  TH_INSTALL_MALWARE,
  TH_IP_ADDR_SPOOFING,
  TH_NONCE_REUSE,
  TH_PHYSICAL_ATTACK,
  TH_REMOVABLE_MEDIA,
  TH_RESOURCE_STARVATION,
  TH_ROOT_TOOLKIT,
  TH_ROUGE_AP,
  TH_ROWHAMMER,
  TH_SHOULDER_SURFING,
  TH_SOCIAL_ENGINEERING,
  TH_SQL_INJECTION,
  TH_SW_REVERSE_ENGINEERING,
  TH_SW_SUPPLY_CHAIN,
  TH_TRY_INVALID_PIN,
  TH_WEAK_SIGNATURE,
} from "./cvss-threat";
import {
  calculateDefaultCvssScore,
  calculateProductCvssScore,
} from "./device-data";

const isDefaultSecurity = true;
let andCnt = 0;

// Root Goals
const goals: Node[] = [
  {
    type: NodeType.ROOT_GOAL,
    desc: "Steal Cryptocurrency",
    children: [
      {
        $or: [
          // { type: NodeType.SUB_GOAL, index: 1 },
          // { type: NodeType.SUB_GOAL, index: 2 },
          // { type: NodeType.SUB_GOAL, index: 3 },
          { type: NodeType.SUB_GOAL, index: 9 },
        ],
      },
    ],
  },
  {
    type: NodeType.ROOT_GOAL,
    desc: "Denial of Service",
    children: [
      {
        $or: [
          { type: NodeType.SUB_GOAL, index: 4 },
          { type: NodeType.SUB_GOAL, index: 5 },
          { type: NodeType.SUB_GOAL, index: 6 },
        ],
      },
    ],
  },
  {
    type: NodeType.ROOT_GOAL,
    desc: "Privacy Breach",
    children: [
      {
        $or: [
          { type: NodeType.SUB_GOAL, index: 7 },
          { type: NodeType.SUB_GOAL, index: 8 },
        ],
      },
    ],
  },
];

// Sub-goals
const subgoals: Node[] = [
  {
    type: NodeType.SUB_GOAL,
    desc: "Obtain a private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 1 },
          { type: NodeType.BRANCH_NODE, index: 4 },
          { type: NodeType.BRANCH_NODE, index: 7 },
          { type: NodeType.BRANCH_NODE, index: 14 },
          { type: NodeType.BRANCH_NODE, index: 17 },
          { type: NodeType.BRANCH_NODE, index: 21 },
          { type: NodeType.BRANCH_NODE, index: 36 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Make the wallet send cryptocurrency to an adversary",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 38 },
          { type: NodeType.BRANCH_NODE, index: 52 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Intercept cryptocurrency",
    children: [{ type: NodeType.BRANCH_NODE, index: 56 }],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Prevent a user from using a private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 68 },
          { type: NodeType.BRANCH_NODE, index: 74 },
          { type: NodeType.BRANCH_NODE, index: 77 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Prevent a user from using the wallet",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 79 },
          { type: NodeType.BRANCH_NODE, index: 83 },
          { type: NodeType.BRANCH_NODE, index: 86 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Prevent a user from communicating with blockchain network",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 89 },
          { type: NodeType.BRANCH_NODE, index: 90 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Obtain account information",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 91 },
          { type: NodeType.BRANCH_NODE, index: 95 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Obtain user's personally identifiable information",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 112 },
          { type: NodeType.BRANCH_NODE, index: 115 },
        ],
      },
    ],
  },
  {
    // Test
    // S9
    type: NodeType.SUB_GOAL,
    desc: "Obtain a private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 129 },
          { type: NodeType.BRANCH_NODE, index: 132 },
        ],
      },
    ],
  },
];

// Branch Nodes
const branchNodes: Node[] = [
  {
    type: NodeType.BRANCH_NODE, // B1
    desc: "Eavesdrop input data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 2 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B2
    desc: "Keylogger malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 3 },
          { type: NodeType.ATTACK_VECTOR, index: 5 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B3
    desc: "Install a malware (keylogger, screen touch input logger)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 1 },
          { type: NodeType.ATTACK_VECTOR, index: 2 },
          { type: NodeType.ATTACK_VECTOR, index: 3 },
          { type: NodeType.ATTACK_VECTOR, index: 4 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B4
    desc: "Eavesdrop output data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 5 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B5
    desc: "Screen capture malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 6 },
          { type: NodeType.ATTACK_VECTOR, index: 10 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B6
    desc: "Install a malware (screen recorder)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 6 },
          { type: NodeType.ATTACK_VECTOR, index: 7 },
          { type: NodeType.ATTACK_VECTOR, index: 8 },
          { type: NodeType.ATTACK_VECTOR, index: 9 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B7
    desc: "Observe output data directly on the screen",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 11 },
          { type: NodeType.BRANCH_NODE, index: 8 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B8
    desc: "Open the wallet and obtain secret data",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 9 },
          { type: NodeType.BRANCH_NODE, index: 10 },
          { type: NodeType.BRANCH_NODE, index: 11 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B9
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 12 },
          { type: NodeType.ATTACK_VECTOR, index: 13 },
          { type: NodeType.ATTACK_VECTOR, index: 14 },
          { type: NodeType.ATTACK_VECTOR, index: 15 },
          { type: NodeType.ATTACK_VECTOR, index: 16 },
          { type: NodeType.ATTACK_VECTOR, index: 17 },
          { type: NodeType.ATTACK_VECTOR, index: 18 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B10
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 19 },
          { type: NodeType.ATTACK_VECTOR, index: 20 },
          { type: NodeType.ATTACK_VECTOR, index: 21 },
          { type: NodeType.ATTACK_VECTOR, index: 22 },
          { type: NodeType.ATTACK_VECTOR, index: 23 },
          { type: NodeType.ATTACK_VECTOR, index: 24 },
          { type: NodeType.ATTACK_VECTOR, index: 25 },
          { type: NodeType.ATTACK_VECTOR, index: 26 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B11
    desc: "Obtain a passphrase",
    children: [
      {
        $or: [
          {
            $or: [
              { type: NodeType.ATTACK_VECTOR, index: 27 },
              { type: NodeType.ATTACK_VECTOR, index: 28 },
              { type: NodeType.ATTACK_VECTOR, index: 29 },
              { type: NodeType.ATTACK_VECTOR, index: 30 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 12 },
              { type: NodeType.BRANCH_NODE, index: 13 },
            ],
          },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B12
    desc: "Install a malware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 31 },
          { type: NodeType.ATTACK_VECTOR, index: 32 },
          { type: NodeType.ATTACK_VECTOR, index: 33 },
          { type: NodeType.ATTACK_VECTOR, index: 34 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B13
    desc: "Execute malware attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 35 },
          { type: NodeType.ATTACK_VECTOR, index: 36 },
          { type: NodeType.ATTACK_VECTOR, index: 37 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B14
    desc: "Obtain a private key or recovery phrase at rest",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 15 },
          { type: NodeType.ATTACK_VECTOR, index: 43 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B15
    desc: "Obtain data at rest (Flash, HDD, SDD)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 38 },
          { type: NodeType.ATTACK_VECTOR, index: 39 },
          { type: NodeType.BRANCH_NODE, index: 16 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B16
    desc: "Get root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 40 },
          { type: NodeType.ATTACK_VECTOR, index: 41 },
          { type: NodeType.ATTACK_VECTOR, index: 42 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B17
    desc: "Obtain data in transit (RAM)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 44 },
          { type: NodeType.BRANCH_NODE, index: 18 },
          { type: NodeType.BRANCH_NODE, index: 20 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B18
    desc: "Clipboard hijacker malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 19 },
          { type: NodeType.ATTACK_VECTOR, index: 49 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B19
    desc: "Install a malware (clipboard hijacker)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 45 },
          { type: NodeType.ATTACK_VECTOR, index: 46 },
          { type: NodeType.ATTACK_VECTOR, index: 47 },
          { type: NodeType.ATTACK_VECTOR, index: 48 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B20
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 50 },
          { type: NodeType.ATTACK_VECTOR, index: 51 },
          { type: NodeType.ATTACK_VECTOR, index: 52 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B21
    desc: "Make the wallet use a known private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 22 },
          { type: NodeType.BRANCH_NODE, index: 27 },
          { type: NodeType.BRANCH_NODE, index: 31 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B22
    desc: "Wallet application modification",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 53 },
              { type: NodeType.BRANCH_NODE, index: 23 },
            ],
          },
          {
            $or: [{ type: NodeType.BRANCH_NODE, index: 26 }],
          },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B23
    desc: "Install a modified application",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 54 },
          { type: NodeType.ATTACK_VECTOR, index: 55 },
          { type: NodeType.BRANCH_NODE, index: 24 },
          { type: NodeType.BRANCH_NODE, index: 25 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B24
    desc: "MITM attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 56 },
          { type: NodeType.ATTACK_VECTOR, index: 57 },
          { type: NodeType.ATTACK_VECTOR, index: 58 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B25
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 59 },
          { type: NodeType.ATTACK_VECTOR, index: 60 },
          { type: NodeType.ATTACK_VECTOR, index: 61 },
          { type: NodeType.ATTACK_VECTOR, index: 62 },
          { type: NodeType.ATTACK_VECTOR, index: 63 },
          { type: NodeType.ATTACK_VECTOR, index: 64 },
          { type: NodeType.ATTACK_VECTOR, index: 65 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B26
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 66 },
          { type: NodeType.ATTACK_VECTOR, index: 67 },
          { type: NodeType.ATTACK_VECTOR, index: 68 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B27
    desc: "Firmware modification",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 69 },
              { type: NodeType.BRANCH_NODE, index: 28 },
            ],
          },
          {
            $or: [{ type: NodeType.ATTACK_VECTOR, index: 82 }],
          },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B28
    desc: "Install a modified firmware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 70 },
          { type: NodeType.ATTACK_VECTOR, index: 71 },
          { type: NodeType.BRANCH_NODE, index: 29 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B29
    desc: "MITM attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 72 },
          { type: NodeType.ATTACK_VECTOR, index: 73 },
          { type: NodeType.ATTACK_VECTOR, index: 74 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B30
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 75 },
          { type: NodeType.ATTACK_VECTOR, index: 76 },
          { type: NodeType.ATTACK_VECTOR, index: 77 },
          { type: NodeType.ATTACK_VECTOR, index: 78 },
          { type: NodeType.ATTACK_VECTOR, index: 79 },
          { type: NodeType.ATTACK_VECTOR, index: 80 },
          { type: NodeType.ATTACK_VECTOR, index: 81 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B31
    desc: "Create or recover a wallet using a known private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 32 },
          { type: NodeType.BRANCH_NODE, index: 34 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B32
    desc:
      "Replace a recovery phrase or private key with an adversary’s using a clipboard malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 33 },
          { type: NodeType.ATTACK_VECTOR, index: 87 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B33
    desc:
      "Replace a recovery phrase or private key with an adversary’s using a clipboard malware",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 83 },
          { type: NodeType.ATTACK_VECTOR, index: 84 },
          { type: NodeType.ATTACK_VECTOR, index: 85 },
          { type: NodeType.ATTACK_VECTOR, index: 86 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B34
    desc: "Access the target device and create or recover a wallet",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 88 },
          { type: NodeType.BRANCH_NODE, index: 35 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B35
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 89 },
          { type: NodeType.ATTACK_VECTOR, index: 90 },
          { type: NodeType.ATTACK_VECTOR, index: 91 },
          { type: NodeType.ATTACK_VECTOR, index: 92 },
          { type: NodeType.ATTACK_VECTOR, index: 93 },
          { type: NodeType.ATTACK_VECTOR, index: 94 },
          { type: NodeType.ATTACK_VECTOR, index: 95 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B36
    desc: "Find a private key using a computational method",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 96 },
          { type: NodeType.BRANCH_NODE, index: 37 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B37
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 97 },
          { type: NodeType.ATTACK_VECTOR, index: 98 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B38
    desc: "Manipulate the recipient address or amount of the transaction",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 39 },
          { type: NodeType.BRANCH_NODE, index: 42 },
          { type: NodeType.BRANCH_NODE, index: 47 },
          { type: NodeType.BRANCH_NODE, index: 51 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B39
    desc: "Modify the clipboard data",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 40 },
          { type: NodeType.ATTACK_VECTOR, index: 103 },
          { type: NodeType.BRANCH_NODE, index: 41 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B40
    desc: "Install a malware (clipboard data modifier)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 99 },
          { type: NodeType.ATTACK_VECTOR, index: 100 },
          { type: NodeType.ATTACK_VECTOR, index: 101 },
          { type: NodeType.ATTACK_VECTOR, index: 102 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B41
    desc: "Bypass user confirmation",
    children: [
      {
        $or: [{ type: NodeType.ATTACK_VECTOR, index: 104 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B42
    desc: "Wallet application (or wallet manager) modification",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 105 },
          { type: NodeType.BRANCH_NODE, index: 43 },
          { type: NodeType.BRANCH_NODE, index: 46 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B43
    desc: "Install a modified application",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 106 },
          { type: NodeType.ATTACK_VECTOR, index: 107 },
          { type: NodeType.BRANCH_NODE, index: 44 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B44
    desc: "MITM attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 108 },
          { type: NodeType.ATTACK_VECTOR, index: 109 },
          { type: NodeType.ATTACK_VECTOR, index: 110 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B45
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 111 },
          { type: NodeType.ATTACK_VECTOR, index: 112 },
          { type: NodeType.ATTACK_VECTOR, index: 113 },
          { type: NodeType.ATTACK_VECTOR, index: 114 },
          { type: NodeType.ATTACK_VECTOR, index: 115 },
          { type: NodeType.ATTACK_VECTOR, index: 116 },
          { type: NodeType.ATTACK_VECTOR, index: 117 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B46
    desc: "Bypass user confirmation",
    children: [
      {
        $or: [{ type: NodeType.ATTACK_VECTOR, index: 118 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B47
    desc: "Wallet firmware modification",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 119 },
          { type: NodeType.BRANCH_NODE, index: 48 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B48
    desc: "Install the modified firmware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 120 },
          { type: NodeType.ATTACK_VECTOR, index: 121 },
          { type: NodeType.BRANCH_NODE, index: 49 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B49
    desc: "MITM attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 122 },
          { type: NodeType.ATTACK_VECTOR, index: 123 },
          { type: NodeType.ATTACK_VECTOR, index: 124 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B50
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 125 },
          { type: NodeType.ATTACK_VECTOR, index: 126 },
          { type: NodeType.ATTACK_VECTOR, index: 127 },
          { type: NodeType.ATTACK_VECTOR, index: 128 },
          { type: NodeType.ATTACK_VECTOR, index: 129 },
          { type: NodeType.ATTACK_VECTOR, index: 130 },
          { type: NodeType.ATTACK_VECTOR, index: 131 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B51
    desc: "Get root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 132 },
          { type: NodeType.ATTACK_VECTOR, index: 133 },
          { type: NodeType.ATTACK_VECTOR, index: 134 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B52
    desc: "Send cryptocurrency using the target wallet directly",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 53 },
          { type: NodeType.BRANCH_NODE, index: 54 },
          { type: NodeType.BRANCH_NODE, index: 55 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B53
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 135 },
          { type: NodeType.ATTACK_VECTOR, index: 136 },
          { type: NodeType.ATTACK_VECTOR, index: 137 },
          { type: NodeType.ATTACK_VECTOR, index: 138 },
          { type: NodeType.ATTACK_VECTOR, index: 139 },
          { type: NodeType.ATTACK_VECTOR, index: 140 },
          { type: NodeType.ATTACK_VECTOR, index: 141 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B54
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 142 },
          { type: NodeType.ATTACK_VECTOR, index: 143 },
          { type: NodeType.ATTACK_VECTOR, index: 144 },
          { type: NodeType.ATTACK_VECTOR, index: 145 },
          { type: NodeType.ATTACK_VECTOR, index: 146 },
          { type: NodeType.ATTACK_VECTOR, index: 147 },
          { type: NodeType.ATTACK_VECTOR, index: 148 },
          { type: NodeType.ATTACK_VECTOR, index: 149 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B55
    desc: "Obtain a passphrase",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 150 },
          { type: NodeType.ATTACK_VECTOR, index: 151 },
          { type: NodeType.ATTACK_VECTOR, index: 152 },
          { type: NodeType.ATTACK_VECTOR, index: 153 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B56
    desc: "Show an adversary’s address as a user’s address",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 57 },
          { type: NodeType.BRANCH_NODE, index: 58 },
          { type: NodeType.BRANCH_NODE, index: 62 },
          { type: NodeType.BRANCH_NODE, index: 66 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B57
    desc: "Get root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 154 },
          { type: NodeType.ATTACK_VECTOR, index: 155 },
          { type: NodeType.ATTACK_VECTOR, index: 156 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B58
    desc: "Wallet application (or wallet manager) modification",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 157 },
          { type: NodeType.BRANCH_NODE, index: 59 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B59
    desc: "Install a modified application",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 158 },
          { type: NodeType.ATTACK_VECTOR, index: 159 },
          { type: NodeType.BRANCH_NODE, index: 60 },
          { type: NodeType.BRANCH_NODE, index: 61 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B60
    desc: "MITM attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 160 },
          { type: NodeType.ATTACK_VECTOR, index: 161 },
          { type: NodeType.ATTACK_VECTOR, index: 162 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B61
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 163 },
          { type: NodeType.ATTACK_VECTOR, index: 164 },
          { type: NodeType.ATTACK_VECTOR, index: 165 },
          { type: NodeType.ATTACK_VECTOR, index: 166 },
          { type: NodeType.ATTACK_VECTOR, index: 167 },
          { type: NodeType.ATTACK_VECTOR, index: 168 },
          { type: NodeType.ATTACK_VECTOR, index: 169 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B62
    desc: "Wallet firmware modification",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 170 },
          { type: NodeType.BRANCH_NODE, index: 63 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B63
    desc: "Install the modified firmware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 171 },
          { type: NodeType.ATTACK_VECTOR, index: 172 },
          { type: NodeType.BRANCH_NODE, index: 64 },
          { type: NodeType.BRANCH_NODE, index: 65 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B64
    desc: "MITM attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 173 },
          { type: NodeType.ATTACK_VECTOR, index: 174 },
          { type: NodeType.ATTACK_VECTOR, index: 175 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B65
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 176 },
          { type: NodeType.ATTACK_VECTOR, index: 177 },
          { type: NodeType.ATTACK_VECTOR, index: 178 },
          { type: NodeType.ATTACK_VECTOR, index: 179 },
          { type: NodeType.ATTACK_VECTOR, index: 180 },
          { type: NodeType.ATTACK_VECTOR, index: 181 },
          { type: NodeType.ATTACK_VECTOR, index: 182 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B66
    desc:
      "Replace a user’s address with an adversary’s using a clipboard hijacker",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 67 },
          { type: NodeType.ATTACK_VECTOR, index: 187 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B67
    desc: "Install a malware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 183 },
          { type: NodeType.ATTACK_VECTOR, index: 184 },
          { type: NodeType.ATTACK_VECTOR, index: 185 },
          { type: NodeType.ATTACK_VECTOR, index: 186 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B68
    desc: "Delete a private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 69 },
          { type: NodeType.BRANCH_NODE, index: 72 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B69
    desc: "Delete a private key using the wallet function",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 70 },
          { type: NodeType.BRANCH_NODE, index: 71 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B70
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 188 },
          { type: NodeType.ATTACK_VECTOR, index: 189 },
          { type: NodeType.ATTACK_VECTOR, index: 190 },
          { type: NodeType.ATTACK_VECTOR, index: 191 },
          { type: NodeType.ATTACK_VECTOR, index: 192 },
          { type: NodeType.ATTACK_VECTOR, index: 193 },
          { type: NodeType.ATTACK_VECTOR, index: 194 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B71
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 195 },
          { type: NodeType.ATTACK_VECTOR, index: 196 },
          { type: NodeType.ATTACK_VECTOR, index: 197 },
          { type: NodeType.ATTACK_VECTOR, index: 198 },
          { type: NodeType.ATTACK_VECTOR, index: 199 },
          { type: NodeType.ATTACK_VECTOR, index: 200 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B72
    desc: "Delete files at rest (HDD, SSD, Flash)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 203 },
          { type: NodeType.BRANCH_NODE, index: 73 },
          { type: NodeType.ATTACK_VECTOR, index: 207 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B73
    desc: "Get root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 204 },
          { type: NodeType.ATTACK_VECTOR, index: 205 },
          { type: NodeType.ATTACK_VECTOR, index: 206 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B74
    desc: "Encrypt a private key",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 75 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B75
    desc: "Ransomware attack",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 76 },
          { type: NodeType.ATTACK_VECTOR, index: 212 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B76
    desc: "Install a malware (ransomware)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 208 },
          { type: NodeType.ATTACK_VECTOR, index: 209 },
          { type: NodeType.ATTACK_VECTOR, index: 210 },
          { type: NodeType.ATTACK_VECTOR, index: 211 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B77
    desc: "Lock the wallet",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 78 },
          { type: NodeType.ATTACK_VECTOR, index: 220 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B78
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 213 },
          { type: NodeType.ATTACK_VECTOR, index: 214 },
          { type: NodeType.ATTACK_VECTOR, index: 215 },
          { type: NodeType.ATTACK_VECTOR, index: 216 },
          { type: NodeType.ATTACK_VECTOR, index: 217 },
          { type: NodeType.ATTACK_VECTOR, index: 218 },
          { type: NodeType.ATTACK_VECTOR, index: 219 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B79
    desc: "Delete the wallet application (or wallet manager)",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 80 },
          { type: NodeType.BRANCH_NODE, index: 81 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B80
    desc:
      "Bypass OS authentication and uninstall the wallet application (or wallet manager)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 221 },
          { type: NodeType.ATTACK_VECTOR, index: 222 },
          { type: NodeType.ATTACK_VECTOR, index: 223 },
          { type: NodeType.ATTACK_VECTOR, index: 224 },
          { type: NodeType.ATTACK_VECTOR, index: 225 },
          { type: NodeType.ATTACK_VECTOR, index: 226 },
          { type: NodeType.ATTACK_VECTOR, index: 227 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B81
    desc: "Delete files at rest (HDD, SSD, Flash)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 228 },
          { type: NodeType.BRANCH_NODE, index: 82 },
          { type: NodeType.ATTACK_VECTOR, index: 232 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B82
    desc: "Get root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 229 },
          { type: NodeType.ATTACK_VECTOR, index: 230 },
          { type: NodeType.ATTACK_VECTOR, index: 231 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B83
    desc: "Encrypt a wallet application (or wallet manager)",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 84 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B84
    desc: "Ransomware attack",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 85 },
          { type: NodeType.ATTACK_VECTOR, index: 237 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B85
    desc: "Install a malware (ransomware)",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 233 },
          { type: NodeType.ATTACK_VECTOR, index: 234 },
          { type: NodeType.ATTACK_VECTOR, index: 235 },
          { type: NodeType.ATTACK_VECTOR, index: 236 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B86
    desc:
      "Prevent a user downloading or updating the wallet application or firmware",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 87 },
          { type: NodeType.BRANCH_NODE, index: 88 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B87
    desc: "DoS attacks on the download server",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 238 },
          { type: NodeType.ATTACK_VECTOR, index: 239 },
          { type: NodeType.ATTACK_VECTOR, index: 240 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B88
    desc:
      "Man-in-the-middle attacks between the wallet and the download server",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 241 },
          { type: NodeType.ATTACK_VECTOR, index: 242 },
          { type: NodeType.ATTACK_VECTOR, index: 243 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B89
    desc:
      "Man-in-the-middle attacks between the wallet application and the blockchain network",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 244 },
          { type: NodeType.ATTACK_VECTOR, index: 245 },
          { type: NodeType.ATTACK_VECTOR, index: 246 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B90
    desc: "DoS attacks on the blockchain node or API server",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 247 },
          { type: NodeType.ATTACK_VECTOR, index: 248 },
          { type: NodeType.ATTACK_VECTOR, index: 249 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B91
    desc:
      "Obtain account information from the wallet application (or wallet manager)",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 92 },
          { type: NodeType.BRANCH_NODE, index: 93 },
          { type: NodeType.BRANCH_NODE, index: 94 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B92
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 250 },
          { type: NodeType.ATTACK_VECTOR, index: 251 },
          { type: NodeType.ATTACK_VECTOR, index: 252 },
          { type: NodeType.ATTACK_VECTOR, index: 253 },
          { type: NodeType.ATTACK_VECTOR, index: 254 },
          { type: NodeType.ATTACK_VECTOR, index: 255 },
          { type: NodeType.ATTACK_VECTOR, index: 256 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B93
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 257 },
          { type: NodeType.ATTACK_VECTOR, index: 258 },
          { type: NodeType.ATTACK_VECTOR, index: 259 },
          { type: NodeType.ATTACK_VECTOR, index: 260 },
          { type: NodeType.ATTACK_VECTOR, index: 261 },
          { type: NodeType.ATTACK_VECTOR, index: 262 },
          { type: NodeType.ATTACK_VECTOR, index: 263 },
          { type: NodeType.ATTACK_VECTOR, index: 264 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B94
    desc: "Obtain a passphrase",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 265 },
          { type: NodeType.ATTACK_VECTOR, index: 266 },
          { type: NodeType.ATTACK_VECTOR, index: 267 },
          { type: NodeType.ATTACK_VECTOR, index: 268 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B95
    desc: "Obtain account information when a user uses the wallet",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 96 },
          { type: NodeType.BRANCH_NODE, index: 99 },
          { type: NodeType.BRANCH_NODE, index: 102 },
          { type: NodeType.BRANCH_NODE, index: 105 },
          { type: NodeType.BRANCH_NODE, index: 109 },
          { type: NodeType.ATTACK_VECTOR, index: 297 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B96
    desc: "Eavesdrop input data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 97 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B97
    desc: "Keylogger (keyboard, mouse, touch screen input logger) malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 98 },
          { type: NodeType.ATTACK_VECTOR, index: 273 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B98
    desc: "Install a malware (keylogger, screen touch input logger)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 269 },
          { type: NodeType.ATTACK_VECTOR, index: 270 },
          { type: NodeType.ATTACK_VECTOR, index: 271 },
          { type: NodeType.ATTACK_VECTOR, index: 272 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B99
    desc: "Eavesdrop output data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 100 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B100
    desc: "Screen recorder malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 101 },
          { type: NodeType.ATTACK_VECTOR, index: 278 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B101
    desc: "Install a malware (screen recorder)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 274 },
          { type: NodeType.ATTACK_VECTOR, index: 275 },
          { type: NodeType.ATTACK_VECTOR, index: 276 },
          { type: NodeType.ATTACK_VECTOR, index: 277 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B102
    desc: "Eavesdrop clipboard data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 103 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B103
    desc: "Clipboard hijacker",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 104 },
          { type: NodeType.ATTACK_VECTOR, index: 283 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B104
    desc: "Install a malware (clipboard hijacker)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 279 },
          { type: NodeType.ATTACK_VECTOR, index: 280 },
          { type: NodeType.ATTACK_VECTOR, index: 281 },
          { type: NodeType.ATTACK_VECTOR, index: 282 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B105
    desc: "Eavesdrop network traffic",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 106 },
          { type: NodeType.BRANCH_NODE, index: 108 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B106
    desc: "Network packet sniffer",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 107 },
          { type: NodeType.ATTACK_VECTOR, index: 288 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B107
    desc: "Install a malware (network packet sniffer)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 284 },
          { type: NodeType.ATTACK_VECTOR, index: 285 },
          { type: NodeType.ATTACK_VECTOR, index: 286 },
          { type: NodeType.ATTACK_VECTOR, index: 287 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B108
    desc: "Man-in-the-middle attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 289 },
          { type: NodeType.ATTACK_VECTOR, index: 290 },
          { type: NodeType.ATTACK_VECTOR, index: 291 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B109
    desc: "Eavesdrop peripheral data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 110 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B110
    desc: "USB packet sniffer",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 111 },
          { type: NodeType.ATTACK_VECTOR, index: 296 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B111
    desc: "USB packet sniffer",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 292 },
          { type: NodeType.ATTACK_VECTOR, index: 293 },
          { type: NodeType.ATTACK_VECTOR, index: 294 },
          { type: NodeType.ATTACK_VECTOR, index: 295 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B112
    desc:
      "Obtain personal information from the wallet application (or wallet manager)",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 113 },
          { type: NodeType.BRANCH_NODE, index: 114 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B113
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 298 },
          { type: NodeType.ATTACK_VECTOR, index: 299 },
          { type: NodeType.ATTACK_VECTOR, index: 300 },
          { type: NodeType.ATTACK_VECTOR, index: 301 },
          { type: NodeType.ATTACK_VECTOR, index: 302 },
          { type: NodeType.ATTACK_VECTOR, index: 303 },
          { type: NodeType.ATTACK_VECTOR, index: 304 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B114
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 305 },
          { type: NodeType.ATTACK_VECTOR, index: 306 },
          { type: NodeType.ATTACK_VECTOR, index: 307 },
          { type: NodeType.ATTACK_VECTOR, index: 308 },
          { type: NodeType.ATTACK_VECTOR, index: 309 },
          { type: NodeType.ATTACK_VECTOR, index: 310 },
          { type: NodeType.ATTACK_VECTOR, index: 311 },
          { type: NodeType.ATTACK_VECTOR, index: 312 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B115
    desc: "Obtain personal information when a user uses the wallet",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 116 },
          { type: NodeType.BRANCH_NODE, index: 119 },
          { type: NodeType.BRANCH_NODE, index: 122 },
          { type: NodeType.BRANCH_NODE, index: 125 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B116
    desc: "Eavesdrop input data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 117 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B117
    desc: "Keylogger (keyboard, mouse, touch screen input logger) malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 118 },
          { type: NodeType.ATTACK_VECTOR, index: 317 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B118
    desc: "Install a malware (keylogger, screen touch input logger)",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 313 },
          { type: NodeType.ATTACK_VECTOR, index: 314 },
          { type: NodeType.ATTACK_VECTOR, index: 315 },
          { type: NodeType.ATTACK_VECTOR, index: 316 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B119
    desc: "Eavesdrop output data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 120 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B120
    desc: "Screen recorder malware",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 121 },
          { type: NodeType.ATTACK_VECTOR, index: 322 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B121
    desc: "Install a malware (screen recorder)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 318 },
          { type: NodeType.ATTACK_VECTOR, index: 319 },
          { type: NodeType.ATTACK_VECTOR, index: 320 },
          { type: NodeType.ATTACK_VECTOR, index: 321 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B122
    desc: "Eavesdrop clipboard data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 123 }],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B123
    desc: "Clipboard hijacker",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 124 },
          { type: NodeType.ATTACK_VECTOR, index: 327 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B124
    desc: "Install a malware (clipboard hijacker)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 323 },
          { type: NodeType.ATTACK_VECTOR, index: 324 },
          { type: NodeType.ATTACK_VECTOR, index: 325 },
          { type: NodeType.ATTACK_VECTOR, index: 326 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B125
    desc: "Eavesdrop network traffic",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 126 },
          { type: NodeType.BRANCH_NODE, index: 128 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B126
    desc: "Network packet sniffer",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 127 },
          { type: NodeType.ATTACK_VECTOR, index: 332 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B127
    desc: "Install a malware (network packet sniffer)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 328 },
          { type: NodeType.ATTACK_VECTOR, index: 329 },
          { type: NodeType.ATTACK_VECTOR, index: 330 },
          { type: NodeType.ATTACK_VECTOR, index: 331 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE, // B128
    desc: "Man-in-the-middle attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 333 },
          { type: NodeType.ATTACK_VECTOR, index: 334 },
          { type: NodeType.ATTACK_VECTOR, index: 335 },
        ],
      },
    ],
  },

  // Test nodes
  {
    type: NodeType.BRANCH_NODE, // B129
    desc: "Eavesdrop input data",
    children: [
      {
        $or: [{ type: NodeType.BRANCH_NODE, index: 130 }],
      },
    ],
  },
  {
    type: NodeType.BRANCH_NODE, // B130
    desc: "Keylogger malware attack",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 131 },
          { type: NodeType.ATTACK_VECTOR, index: 340 },
        ],
      },
    ],
  },
  {
    type: NodeType.BRANCH_NODE, // B131
    desc: "Install a keylogger malware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 336 },
          { type: NodeType.ATTACK_VECTOR, index: 337 },
          { type: NodeType.ATTACK_VECTOR, index: 338 },
          { type: NodeType.ATTACK_VECTOR, index: 339 },
        ],
      },
    ],
  },
  {
    type: NodeType.BRANCH_NODE, // B132
    desc: "Observe output data directly on the screen",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 341 },
          { type: NodeType.BRANCH_NODE, index: 133 },
        ],
      },
    ],
  },
  {
    type: NodeType.BRANCH_NODE, // B133
    desc: "Open the wallet and obtain secret data",
    children: [
      {
        $and: [
          { type: NodeType.BRANCH_NODE, index: 134 },
          { type: NodeType.BRANCH_NODE, index: 135 },
        ],
      },
    ],
  },
  {
    type: NodeType.BRANCH_NODE, // B134
    desc: "Bypass OS authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 342 },
          { type: NodeType.ATTACK_VECTOR, index: 343 },
          { type: NodeType.ATTACK_VECTOR, index: 344 },
          { type: NodeType.ATTACK_VECTOR, index: 345 },
          { type: NodeType.ATTACK_VECTOR, index: 346 },
          { type: NodeType.ATTACK_VECTOR, index: 347 },
          { type: NodeType.ATTACK_VECTOR, index: 348 },
        ],
      },
    ],
  },
  {
    type: NodeType.BRANCH_NODE, // B135
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 349 },
          { type: NodeType.ATTACK_VECTOR, index: 350 },
          { type: NodeType.ATTACK_VECTOR, index: 351 },
          { type: NodeType.ATTACK_VECTOR, index: 352 },
          { type: NodeType.ATTACK_VECTOR, index: 353 },
          { type: NodeType.ATTACK_VECTOR, index: 354 },
          { type: NodeType.ATTACK_VECTOR, index: 355 },
        ],
      },
    ],
  },
];

// Attack Vectors
export const attacks: Node[] = [
  {
    type: NodeType.ATTACK_VECTOR, // T1
    desc: "Install a keylogger(keyboard, mouse, and touch screen input)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T2
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T3
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T4
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T5
    desc: "Execute keylogging attack",
    cvssScore: TH_EXECUTE_KEY_LOGGING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T6
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T7
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T8
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T9
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T10
    desc: "Execute screen capture attack",
    cvssScore: TH_EXECUTE_SCREEN_RECORDING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T11
    desc: "Shoulder-surfing attack (smartphone, surveillance camera)",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T12
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T13
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T14
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T15
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T16
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T17
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T18
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T19
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T20
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T21
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T22
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T23
    desc: "Physical access when the wallet is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T24
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T25
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T26
    desc:
      "Obtain auth credentials using a malware (keylogger, screen recorder, trojan)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T27
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T28
    desc: "Brute-force attack",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T29
    desc:
      "Physical attack (fault injection, probing, microscoping, cold boot attack)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T30
    desc: "Connect a debugger (JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T31
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T32
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T33
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T34
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T35
    desc: "Screen recorder malware",
    cvssScore: TH_EXECUTE_SCREEN_RECORDING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T36
    desc: "Screen recorder malware",
    cvssScore: TH_EXECUTE_CLIPBOARD_HIJACKING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T37
    desc: "Keylogger malware",
    cvssScore: TH_EXECUTE_KEY_LOGGING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T38
    desc: "Connect a debugger (JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T39
    desc:
      "Physical attack (fault injection, probing, microscoping, cold boot attack)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T40
    desc: "Android root toolkit",
    cvssScore: TH_ROOT_TOOLKIT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T41
    desc: "Buffer overflow (code injection)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T42
    desc: "Row Hammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T43
    desc: "Decrypt a private key or recovery phrase",
    cvssScore: TH_DECRYPT_DATA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T44
    desc: "Cold boot attack",
    cvssScore: TH_COLD_BOOT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T45
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T46
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T47
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T48
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T49
    desc: "Execute clipboard hijacking attack",
    cvssScore: TH_EXECUTE_CLIPBOARD_HIJACKING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T50
    desc: "Android root toolkit",
    cvssScore: TH_ROOT_TOOLKIT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T51
    desc: "Buffer overflow (code injection)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T52
    desc: "Row Hammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T53
    desc: "Application reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T54
    desc: "Social engineering (phishing)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T55
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T56
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T57
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T58
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T59
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T60
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T61
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T62
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T63
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T64
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T65
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T66
    desc: "Android root toolkit",
    cvssScore: TH_ROOT_TOOLKIT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T67
    desc: "Buffer overflow (code injection)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T68
    desc: "Row Hammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T69
    desc: "Firmware reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T70
    desc: "Social engineering (phishing)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T71
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T72
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T73
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T74
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T75
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T76
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T77
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T78
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T79
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T80
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T81
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T82
    desc: "Connect a debugger (JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T83
    desc: "Social engineering",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T84
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T85
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T86
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T87
    desc: "Execute clipboard data modification attack",
    cvssScore: TH_EXECUTE_CLIPBOARD_HIJACKING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T88
    desc: "Access the target device physically",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T89
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T90
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T91
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T92
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T93
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T94
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T95
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T96
    desc: "Brute-force attack on a private key",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T97
    desc: "ECDSA weak signature",
    cvssScore: TH_WEAK_SIGNATURE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T98
    desc: "ECDSA nonce reuse",
    cvssScore: TH_NONCE_REUSE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T99
    desc: "Social engineering",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T100
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T101
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T102
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T103
    desc: "Clipboard data modification attack",
    cvssScore: TH_EXECUTE_CLIPBOARD_HIJACKING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T104
    desc: "Access the target wallet and bypass user confirmation",
    cvssScore: TH_BYPASS_USER_CONFIRMATION,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T105
    desc: "Application reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T106
    desc: "Social engineering (phishing)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T107
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T108
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T109
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T110
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T111
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T112
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T113
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T114
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T115
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T116
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T117
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T118
    desc: "Access the target wallet and bypass user confirmation",
    cvssScore: TH_BYPASS_USER_CONFIRMATION,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T119
    desc: "Firmware reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T120
    desc: "Social engineering (phishing)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T121
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T122
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T123
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T124
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T125
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T126
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T127
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T128
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T129
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T130
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T131
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T132
    desc: "Android root toolkit",
    cvssScore: TH_ROOT_TOOLKIT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T133
    desc: "Buffer overflow (code injection)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T134
    desc: "Row Hammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T135
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T136
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T137
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T138
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T139
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T140
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T141
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T142
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T143
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T144
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T145
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T146
    desc: "Physical access when the wallet is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T147
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T148
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T149
    desc:
      "Obtain auth credentials using a malware (keylogger, screen recorder)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T150
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T151
    desc: "Brute-force attack",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T152
    desc:
      "Physical attack (fault injection, probing, microscoping, cold boot attack)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T153
    desc: "Connect a debugger (JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T154
    desc: "Android root toolkit",
    cvssScore: TH_ROOT_TOOLKIT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T155
    desc: "Buffer overflow (code injection)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T156
    desc: "Row Hammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T157
    desc: "Application reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T158
    desc: "Social engineering (phishing)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T159
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T160
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T161
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T162
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T163
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T164
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T165
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T166
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T167
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T168
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T169
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T170
    desc: "Firmware reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T171
    desc: "Social engineering (phishing)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T172
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T173
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T174
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T175
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T176
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T177
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T178
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T179
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T180
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T181
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T182
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T183
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T184
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T185
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T186
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T187
    desc: "Execute clipboard hijacking attack",
    cvssScore: TH_EXECUTE_CLIPBOARD_HIJACKING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T188
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T189
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T190
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T191
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T192
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T193
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T194
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T195
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T196
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T197
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T198
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T199
    desc: "Physical access when the wallet is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T200
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T201
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T202
    desc:
      "Obtain auth credentials using a malware (keylogger, screen recorder, trojan)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T203
    desc: "Delete key files using factory reset or disk formatting",
    cvssScore: TH_FACTORY_RESET_DISK_FORMATTING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T204
    desc: "Android root toolkit",
    cvssScore: TH_ROOT_TOOLKIT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T205
    desc: "Buffer overflow (code injection)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T206
    desc: "Row Hammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T207
    desc: "Connect a debugger (JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T208
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T209
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T210
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T211
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T212
    desc: "Execute ransomware attack",
    cvssScore: TH_EXECUTE_RANSOMWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T213
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T214
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T215
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T216
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T217
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T218
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T219
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T220
    desc: "Keep trying the wrong PIN or password until the wallet is locked",
    cvssScore: TH_TRY_INVALID_PIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T221
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T222
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T223
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T224
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T225
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T226
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T227
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T228
    desc:
      "Delete the wallet application (or wallet manager) using factory reset or disk formatting",
    cvssScore: TH_FACTORY_RESET_DISK_FORMATTING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T229
    desc: "Android root toolkit",
    cvssScore: TH_ROOT_TOOLKIT,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T230
    desc: "Buffer overflow (code injection)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T231
    desc: "Row Hammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T232
    desc: "Connect a debugger (JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T233
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T234
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T235
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T236
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T237
    desc: "Execute ransomware attack",
    cvssScore: TH_EXECUTE_RANSOMWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T238
    desc: "Resource starvation (botnet, flooding attacks)",
    cvssScore: TH_RESOURCE_STARVATION,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T239
    desc: "Ransomware attack",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T240
    desc: "SQL injection",
    cvssScore: TH_SQL_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T241
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T242
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T243
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T244
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T245
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T246
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T247
    desc: "Resource starvation (botnet, flooding attacks)",
    cvssScore: TH_RESOURCE_STARVATION,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T248
    desc: "Ransomware attack",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T249
    desc: "SQL injection",
    cvssScore: TH_SQL_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T250
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T251
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T252
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T253
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T254
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T255
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T256
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T257
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T258
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T259
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T260
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T261
    desc: "Physical access when the wallet is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T262
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T263
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T264
    desc:
      "Obtain auth credentials using a malware (keylogger, screen recorder, trojan)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T265
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T266
    desc: "Brute-force attack",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T267
    desc:
      "Physical attack (fault injection, probing, microscoping, cold boot attack)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T268
    desc: "Connect a debugger (JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T269
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T270
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T271
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T272
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T273
    desc: "Execute keylogger attack",
    cvssScore: TH_EXECUTE_KEY_LOGGING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T274
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T275
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T276
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T277
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T278
    desc: "Execute screen recording attack",
    cvssScore: TH_EXECUTE_SCREEN_RECORDING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T279
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T280
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T281
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T282
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T283
    desc: "Execute clipboard hijacking attack",
    cvssScore: TH_EXECUTE_CLIPBOARD_HIJACKING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T284
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T285
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T286
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T287
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T288
    desc: "Execute network packet sniffing attack",
    cvssScore: TH_EXECUTE_NETWORK_PACKET_SNIFFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T289
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T290
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T291
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T292
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T293
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T294
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T295
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T296
    desc: "Execute USB packet sniffing attack",
    cvssScore: TH_EXECUTE_USB_PACKET_SNIFFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T297
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T298
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T299
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T300
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T301
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T302
    desc: "Physical access when the host is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T303
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T304
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T305
    desc: "Brute-force attack (guessing, dictionary attack)",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T306
    desc: "Buffer overflow (code reuse)",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T307
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T308
    desc: "Fake biometrics",
    cvssScore: TH_FAKE_BIOMETRICS,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T309
    desc: "Physical access when the wallet is open",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T310
    desc: "Shoulder-surfing attack",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T311
    desc: "Physical attack (fault injection(glitching))",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T312
    desc:
      "Obtain auth credentials using a malware (keylogger, screen recorder, trojan)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T313
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T314
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T315
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T316
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T317
    desc: "Execute keylogger attack",
    cvssScore: TH_EXECUTE_KEY_LOGGING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T318
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T319
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T320
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T321
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T322
    desc: "Execute screen recording attack",
    cvssScore: TH_EXECUTE_SCREEN_RECORDING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T323
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T324
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T325
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T326
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T327
    desc: "Execute clipboard hijacking attack",
    cvssScore: TH_EXECUTE_CLIPBOARD_HIJACKING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T328
    desc:
      "Social engineering (malicious files, malvertising, phishing, drive-by download attack)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T329
    desc: "Rouge AP",
    cvssScore: TH_ROUGE_AP,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T330
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T331
    desc: "Removable media (USB drive)",
    cvssScore: TH_REMOVABLE_MEDIA,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T332
    desc: "Execute network packet sniffing attack",
    cvssScore: TH_EXECUTE_NETWORK_PACKET_SNIFFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T333
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T334
    desc: "DNS spoofing and poisoning",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR, // T335
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },

  // Test nodes
  {
    type: NodeType.ATTACK_VECTOR, // T336
    desc: "Social engineering",
    cvssScore: isDefaultSecurity
      ? [AV.N, AC.L, PR.L, UI.R, TC.M, EX.P, EQ.S]
      : [AV.L, AC.H, PR.L, UI.R, TC.M, EX.P, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T337
    desc: "Rogue AP",
    cvssScore: isDefaultSecurity
      ? [AV.L, AC.L, PR.N, UI.R, TC.M, EX.P, EQ.S]
      : [AV.L, AC.L, PR.N, UI.R, TC.M, EX.P, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T338
    desc: "Supply chain attack",
    cvssScore: isDefaultSecurity
      ? [AV.N, AC.H, PR.N, UI.R, TC.M, EX.E, EQ.S]
      : [AV.L, AC.H, PR.N, UI.R, TC.M, EX.E, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T339
    desc: "Removable media",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.N, EX.L, EQ.S]
      : [AV.P, AC.H, PR.N, UI.N, TC.N, EX.L, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T340
    desc: "Execute keylogging attack",
    cvssScore: isDefaultSecurity
      ? [AV.N, AC.L, PR.L, UI.R, TC.N, EX.L, EQ.S]
      : [AV.L, AC.L, PR.L, UI.R, TC.N, EX.L, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T341
    desc: "Shoulder-surfing attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.R, TC.N, EX.L, EQ.S]
      : [AV.P, AC.H, PR.N, UI.R, TC.N, EX.L, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T342
    desc: "Brute-force attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.L, PR.N, UI.N, TC.E, EX.L, EQ.P]
      : [AV.P, AC.L, PR.N, UI.N, TC.E, EX.L, EQ.P],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T343
    desc: "Buffer over flow",
    cvssScore: isDefaultSecurity
      ? [AV.A, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S]
      : [AV.L, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T344
    desc: "Evil maid attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.S]
      : [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T345
    desc: "Fake biometrics",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.N, EX.P, EQ.P]
      : [AV.P, AC.H, PR.N, UI.N, TC.N, EX.P, EQ.P],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T346
    desc: "Physical access when the host is open",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.N, EX.L, EQ.S]
      : [AV.P, AC.H, PR.N, UI.N, TC.N, EX.L, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T347
    desc: "Shoulder-surfing attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.R, TC.N, EX.L, EQ.S]
      : [AV.P, AC.H, PR.N, UI.R, TC.N, EX.L, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T348
    desc: "Physical attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.P]
      : [AV.P, AC.H, PR.N, UI.N, TC.E, EX.E, EQ.B],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T349
    desc: "Brute-force attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.L, PR.N, UI.N, TC.E, EX.L, EQ.P]
      : [AV.P, AC.L, PR.N, UI.N, TC.E, EX.L, EQ.P],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T350
    desc: "Buffer over flow",
    cvssScore: isDefaultSecurity
      ? [AV.A, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S]
      : [AV.L, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T351
    desc: "Evil maid attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.S]
      : [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T352
    desc: "Fake biometrics",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.N, EX.P, EQ.P]
      : [AV.P, AC.H, PR.N, UI.N, TC.N, EX.P, EQ.P],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T353
    desc: "Physical access when the host is open",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.N, EX.L, EQ.S]
      : [AV.P, AC.H, PR.N, UI.N, TC.N, EX.L, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T354
    desc: "Shoulder-surfing attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.R, TC.N, EX.L, EQ.S]
      : [AV.P, AC.H, PR.N, UI.R, TC.N, EX.L, EQ.S],
  },
  {
    type: NodeType.ATTACK_VECTOR, // T355
    desc: "Physical attack",
    cvssScore: isDefaultSecurity
      ? [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.P]
      : [AV.P, AC.H, PR.N, UI.N, TC.E, EX.E, EQ.B],
  },
];

const getNode = (nodeInfo: NodeInfo): Node => {
  if (nodeInfo.type === NodeType.ROOT_GOAL) {
    return goals[nodeInfo.index - 1];
  } else if (nodeInfo.type === NodeType.SUB_GOAL) {
    return subgoals[nodeInfo.index - 1];
  } else if (nodeInfo.type === NodeType.BRANCH_NODE) {
    return branchNodes[nodeInfo.index - 1];
  } else {
    return attacks[nodeInfo.index - 1];
  }
};

const isNodeAvailable = (nodeInfo: NodeInfo, device: DeviceInfo): boolean => {
  if (nodeInfo.type === NodeType.ROOT_GOAL) {
    if (device.productRemoved.goals[nodeInfo.index]) return false;
  } else if (nodeInfo.type === NodeType.SUB_GOAL) {
    if (device.productRemoved.subgoals[nodeInfo.index]) return false;
  } else if (nodeInfo.type === NodeType.BRANCH_NODE) {
    if (device.productRemoved.branchnodes[nodeInfo.index]) return false;
  } else if (nodeInfo.type === NodeType.ATTACK_VECTOR) {
    if (device.productRemoved.attacks[nodeInfo.index]) return false;
  }

  return true;
};

export const calculateJointProbability = (children: NewNodeDatum[]): number => {
  let matrix: number[][] = [];
  let probability = 0;

  // create matrix
  const createMatrix = (
    index: number,
    value: boolean,
    row: number[],
    valueCnt: number,
  ) => {
    // last
    if (index >= children.length - 1) {
      if (value === true) {
        row.push(children[index].cvssScore);
        const prob: number = row.reduce(
          (accum: number, element: number): number => {
            accum *= element;
            return accum;
          },
          1,
        );
        probability += prob;
        row.push(prob);
        matrix.push(row);
      } else {
        // if all falses
        if (valueCnt === 0) return;

        row.push(1 - children[index].cvssScore);
        const prob: number = row.reduce(
          (accum: number, element: number): number => {
            accum *= element;
            return accum;
          },
          1,
        );
        probability += prob;
        row.push(prob);
        matrix.push(row);
      }
    } else {
      if (value === true) {
        row.push(children[index].cvssScore);
      } else {
        row.push(1 - children[index].cvssScore);
      }

      // true
      createMatrix(index + 1, true, row.concat([]), valueCnt + 1);

      // false
      createMatrix(index + 1, false, row.concat([]), valueCnt);
    }
  };

  // true
  createMatrix(0, true, [], 1);

  // false
  createMatrix(0, false, [], 0);

  console.log("this is the test line.");
  return probability;
};

export const generateTree = (
  node: Node,
  index: number,
  device: DeviceInfo,
): NewNodeDatum => {
  let resultNode: NewNodeDatum = {
    name: "",
    attributes: { type: "" },
    cvssScore: 0,
  };

  if (node === undefined || node.type === undefined) {
    resultNode.name = "no type";
    console.log("node doesn't have type property: ", node);
  }

  if (node.type === NodeType.ROOT_GOAL) {
    resultNode.name = `G${index}`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      device: device.name,
      type: "Goal",
      desc: node.desc,
    });
  } else if (node.type === NodeType.SUB_GOAL) {
    resultNode.name = `S${index}`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      type: "Sub Goal",
      desc: node.desc,
    });
  } else if (node.type === NodeType.BRANCH_NODE) {
    resultNode.name = `B${index}`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      type: "Branch Node",
      desc: node.desc,
    });
  } else if (node.type === NodeType.ATTACK_VECTOR) {
    resultNode.name = `T${index}`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      type: "Threat Node",
      desc: node.desc,
    });
  } else if (node.type === NodeType.AND) {
    resultNode.name = `AND`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      type: "AND",
    });
  }

  const handleChildren = (nodeInfoX: NodeInfoX): RawNodeDatum[] => {
    const tempNodeInfoX = nodeInfoX as any;

    if (tempNodeInfoX["$or"]) {
      let orResult: RawNodeDatum[] = [];
      const orChild = nodeInfoX as OperatorOr;
      orChild.$or.forEach((grandInfoX: NodeInfoX) => {
        orResult = orResult.concat(handleChildren(grandInfoX));
      });
      return orResult;
    } else if (tempNodeInfoX["$and"]) {
      const andChild = nodeInfoX as OperatorAnd;
      const newAndNode: Node = {
        type: NodeType.AND,
        desc: "AND",
        children: andChild.$and,
      };
      return [generateTree(newAndNode, 0, device)];
    } else {
      const nodeInfo: NodeInfo = nodeInfoX as NodeInfo;
      // check if it is a removed node.
      if (isNodeAvailable(nodeInfo, device)) {
        const node = getNode(nodeInfo);
        return [generateTree(node, nodeInfo.index, device)];
      }
      // return an empty array when it is a removed node.
      return [];
    }
  };

  if (node.children && node.children.length) {
    let resultChildren: RawNodeDatum[] = [];

    node.children.forEach((childNode) => {
      resultChildren = resultChildren.concat(handleChildren(childNode));
    });

    resultNode = Object.assign({}, resultNode, { children: resultChildren });
  }

  // calcaulte cvss scores
  switch (node.type) {
    case NodeType.ATTACK_VECTOR: {
      const defaultScore: number = calculateDefaultCvssScore(node.cvssScore);
      const changedScore: number = calculateProductCvssScore(
        node.cvssScore as number[],
        device.productImpacted.attacks[index],
      );
      resultNode.cvssScore = changedScore;
      resultNode.attributes = Object.assign(resultNode.attributes, {
        default: defaultScore.toFixed(2) + "",
        calculated: changedScore.toFixed(2) + "",
      });
      break;
    }
    case NodeType.BRANCH_NODE: {
      if (resultNode.children && resultNode.children.length) {
        const cvssScore = calculateJointProbability(resultNode.children);
        resultNode.cvssScore = cvssScore;
        resultNode.attributes = Object.assign(resultNode.attributes, {
          calculated: cvssScore.toFixed(2) + "",
        });
      } else {
        resultNode.attributes = Object.assign(resultNode.attributes, {
          calculated: 0,
        });
      }
      break;
    }
    case NodeType.AND: {
      if (resultNode.children && resultNode.children.length) {
        const cvssScore = resultNode.children.reduce(
          (acumm: number, child: NewNodeDatum): number => {
            if (child.attributes !== undefined) {
              acumm *= child.cvssScore;
            }

            return acumm;
          },
          1,
        );
        resultNode.cvssScore = cvssScore;
        resultNode.attributes = Object.assign(resultNode.attributes, {
          calculated: cvssScore.toFixed(2) + "",
        });
      } else {
        resultNode.attributes = Object.assign(resultNode.attributes, {
          calculated: 0,
        });
      }
      break;
    }
    case NodeType.SUB_GOAL: {
      if (resultNode.children) {
        const cvssScore = calculateJointProbability(resultNode.children);
        resultNode.cvssScore = cvssScore;
        resultNode.attributes = Object.assign(resultNode.attributes, {
          calculated: cvssScore.toFixed(2) + "",
        });
      }
      break;
    }
    case NodeType.ROOT_GOAL: {
      if (resultNode.children) {
        const cvssScore = calculateJointProbability(resultNode.children);
        resultNode.cvssScore = cvssScore;
        resultNode.attributes = Object.assign(resultNode.attributes, {
          calculated: cvssScore.toFixed(2) + "",
        });
      }
      break;
    }
    default: {
      break;
    }
  }

  return resultNode;
};

export const generateAttackTree = (
  device: DeviceInfo,
  goalIndex: number,
): RawNodeDatum => {
  const result: RawNodeDatum = generateTree(
    goals[goalIndex - 1],
    goalIndex,
    device,
  );
  return result;
};

const getCptForParents = (
  parentIds: string[],
  isAndNode: boolean,
): ICptWithoutParents | ICptWithParents => {
  let count = 0;
  const cpt: ICptWithoutParents | ICptWithParents = [];
  let isFirst = true;

  parentIds.forEach(() => {
    count = count << 1;
    count = count + 1;
  });

  if (isAndNode) {
    // AND node
    while (count >= 0) {
      const when: Record<string, string> = {};
      for (let i = 0; i < parentIds.length; i++) {
        const posVal = 1 << i;
        Object.assign(when, {
          [parentIds[i]]: (posVal & count) === 0 ? "F" : "T",
        });
        //when[parentIds[i]] = (posVal & count) === 0 ? "F" : "T";
      }
      if (isFirst === true) {
        cpt.push({ when, then: { T: 1.0, F: 0.0 } });
        isFirst = false;
      } else cpt.push({ when, then: { T: 0.0, F: 1.0 } });
      count--;
    }
  } else {
    // OR node
    while (count >= 0) {
      const when: Record<string, string> = {};
      for (let i = 0; i < parentIds.length; i++) {
        const posVal = 1 << i;
        Object.assign(when, {
          [parentIds[i]]: (posVal & count) === 0 ? "F" : "T",
        });
        // when[parentIds[i]] = (posVal & count) === 0 ? "F" : "T";
      }
      if (count !== 0) cpt.push({ when, then: { T: 1.0, F: 0.0 } });
      else cpt.push({ when, then: { T: 0.0, F: 1.0 } });
      count--;
    }
  }
  return cpt;
};

export const addBNInfo = (
  attackTree: RawNodeDatum,
  networkContainer: NetworkContainer,
): BNNodeDatum => {
  // if already registered in the BN nodes then just add the parent and skip.

  if (attackTree.children) {
    const isAndNode =
      (attackTree.attributes as any)["type"] === "AND" ? true : false;
    const parentIds: string[] = attackTree.children.map((childTree): string => {
      const parentBN = addBNInfo(childTree, networkContainer);
      return parentBN.id;
    });

    const id: string = isAndNode ? attackTree.name + andCnt++ : attackTree.name;

    const bnNode: INode = {
      id,
      states: ["T", "F"],
      parents: parentIds,
      cpt: getCptForParents(parentIds, isAndNode),
    };

    const result: BNNodeDatum = Object.assign(attackTree, bnNode);

    networkContainer.network = addNode(networkContainer.network, bnNode);
    // networkContainer.network = Object.assign({}, networkContainer.network, {
    //   [result.id]: bnNode
    // });
    return result;
  } else {
    const attrs = attackTree.attributes as Record<string, string>;
    const calculated: number = Number(attrs["calculated"]);

    const bnNode: INode = {
      id: attackTree.name,
      states: ["T", "F"],
      parents: [],
      cpt: { T: calculated, F: Number((1.0 - calculated).toPrecision(2)) },
    };
    const result: BNNodeDatum = Object.assign(attackTree, bnNode);

    networkContainer.network = addNode(networkContainer.network, bnNode);
    // networkContainer.network = Object.assign({}, networkContainer.network, {
    //   [result.id]: bnNode
    // });
    return result;
  }
};

export const sortNetwork = (networkContainer: NetworkContainer) => {
  const network = networkContainer.network;
  const keys: string[] = Object.keys(network);
  keys.sort((a, b) => a.localeCompare(b));

  const newNetwork: INetwork = {};
  keys.forEach((key) => {
    newNetwork[key] = network[key];
  });
  networkContainer.network = newNetwork;
};
