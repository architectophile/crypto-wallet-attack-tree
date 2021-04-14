import { RawNodeDatum } from "react-d3-tree/lib/types/common";
import {
  DeviceInfo,
  NewNodeDatum,
  Node,
  NodeInfo,
  NodeInfoX,
  NodeType,
  OperatorAnd,
  OperatorOr,
} from "./common";
import { AC, AV, PR, TC, UI } from "./cvss";
import {
  TH_ACCESS_PHYSICALLY,
  TH_ACCESS_WHEN_UNLOCKED,
  TH_ARP_SPOOFING,
  TH_BRUTE_FORCE,
  TH_BUFFER_OVERFLOW,
  TH_BYPASS_ACCESS_CONTROL,
  TH_BYPASS_OS_AUTH,
  TH_BYPASS_USER_CONFIRMATION,
  TH_CODE_INJECTION,
  TH_COLD_BOOT,
  TH_CONNECT_DEBUGGER,
  TH_DDoS_ATTACK,
  TH_DNS_SPOOFING,
  TH_DUMP_FILES,
  TH_EVIL_MAID,
  TH_FIND_SAME_SIGNATURES,
  TH_GUESS,
  TH_HW_REVERSE_ENGINEERING,
  TH_HW_SUPPLY_CHAIN,
  TH_INSTALL_MALWARE,
  TH_INSTALL_MALWARE_ON_ROOTED,
  TH_IP_ADDR_SPOOFING,
  TH_OBTAIN_PASSPHRASE,
  TH_PHYSICAL_ATTACK,
  TH_ROWHAMMER,
  TH_SHOULDER_SURFING,
  TH_SOCIAL_ENGINEERING,
  TH_SW_REVERSE_ENGINEERING,
  TH_SW_SUPPLY_CHAIN,
  TH_TRY_INVALID_PIN,
} from "./cvss-threat";
import {
  calculateDefaultCvssScore,
  calculateProductCvssScore,
} from "./device-data";

const goals: Node[] = [
  {
    type: NodeType.ROOT_GOAL,
    desc: "Steal Cryptocurrency",
    children: [
      {
        $or: [
          { type: NodeType.SUB_GOAL, index: 1 },
          { type: NodeType.SUB_GOAL, index: 2 },
          { type: NodeType.SUB_GOAL, index: 3 },
          // { type: NodeType.SUB_GOAL, index: 9 },
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

const subgoals: Node[] = [
  {
    type: NodeType.SUB_GOAL,
    desc: "Obtain a private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 1 },
          { type: NodeType.BRANCH_NODE, index: 3 },
          { type: NodeType.BRANCH_NODE, index: 8 },
          { type: NodeType.BRANCH_NODE, index: 14 },
          { type: NodeType.BRANCH_NODE, index: 21 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Make a target device send cryptocurrency to an adversary",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 24 },
          { type: NodeType.BRANCH_NODE, index: 34 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Intercept cryptocurrency",
    children: [
      { type: NodeType.BRANCH_NODE, index: 37 },
      { type: NodeType.BRANCH_NODE, index: 86 },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Prevent from accessing the private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 47 },
          { type: NodeType.BRANCH_NODE, index: 55 },
        ],
      },
    ],
  },
  {
    type: NodeType.SUB_GOAL,
    desc: "Prevent from accessing the wallet application",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 56 },
          { type: NodeType.BRANCH_NODE, index: 60 },
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
          { type: NodeType.BRANCH_NODE, index: 61 },
          { type: NodeType.ATTACK_VECTOR, index: 101 },
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
          { type: NodeType.BRANCH_NODE, index: 62 },
          { type: NodeType.BRANCH_NODE, index: 65 },
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
          { type: NodeType.BRANCH_NODE, index: 70 },
          { type: NodeType.BRANCH_NODE, index: 75 },
          { type: NodeType.BRANCH_NODE, index: 78 },
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
          { type: NodeType.BRANCH_NODE, index: 86 },
          { type: NodeType.BRANCH_NODE, index: 87 },
          { type: NodeType.BRANCH_NODE, index: 88 },
        ],
      },
    ],
  },
];

const branchNodes: Node[] = [
  {
    type: NodeType.BRANCH_NODE,
    desc:
      "Obtain recovery words or private keys when they are entered by a user",
    children: [{ type: NodeType.BRANCH_NODE, index: 2 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop input data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 1 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Obtain recovery phrase or a private key when they are displayed",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 4 },
          { type: NodeType.BRANCH_NODE, index: 7 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Observe data on the display device directly",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 2 },
              { type: NodeType.BRANCH_NODE, index: 5 },
              { type: NodeType.ATTACK_VECTOR, index: 10 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 11 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 3 },
          { type: NodeType.ATTACK_VECTOR, index: 4 },
          { type: NodeType.ATTACK_VECTOR, index: 5 },
          { type: NodeType.ATTACK_VECTOR, index: 6 },
          { type: NodeType.BRANCH_NODE, index: 6 },
          { type: NodeType.ATTACK_VECTOR, index: 9 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Brute-force attack",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 7 },
          { type: NodeType.ATTACK_VECTOR, index: 8 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop output data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 12 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Obtain recovery phrase or a private key from data storage",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 9 },
              { type: NodeType.ATTACK_VECTOR, index: 18 },
            ],
          },
          { type: NodeType.BRANCH_NODE, index: 11 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc:
      "Obtain recovery phrase or a private key data at rest(Flash, HDD, SSD",
    children: [
      {
        $or: [
          {
            $or: [
              { type: NodeType.ATTACK_VECTOR, index: 13 },
              { type: NodeType.ATTACK_VECTOR, index: 14 },
            ],
          },
          {
            $and: [
              {
                $or: [
                  { type: NodeType.ATTACK_VECTOR, index: 15 },
                  { type: NodeType.ATTACK_VECTOR, index: 16 },
                ],
              },
              { type: NodeType.ATTACK_VECTOR, index: 17 },
            ],
          },
          { type: NodeType.BRANCH_NODE, index: 10 },
        ],
      },
    ],
  },

  {
    // 10
    type: NodeType.BRANCH_NODE,
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 19 },
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 20 },
              { type: NodeType.ATTACK_VECTOR, index: 21 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 22 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Obtain recovery phrase or a private key data in transit(RAM)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 23 },
          { type: NodeType.BRANCH_NODE, index: 12 },
          { type: NodeType.BRANCH_NODE, index: 13 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 24 },
              { type: NodeType.ATTACK_VECTOR, index: 25 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 26 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Obtain the clipboard data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 27 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a target device generate a known private key",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 15 },
              { type: NodeType.BRANCH_NODE, index: 16 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 17 },
              { type: NodeType.BRANCH_NODE, index: 18 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 19 },
              { type: NodeType.BRANCH_NODE, index: 20 },
            ],
          },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the app to generate a known private key",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 28 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a user install the modified app",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 29 },
          { type: NodeType.ATTACK_VECTOR, index: 30 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the firmware to generate a known private key",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 31 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a user install the modified firmware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 32 },
          { type: NodeType.ATTACK_VECTOR, index: 33 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the wallet device",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 34 }],
  },

  {
    // 20
    type: NodeType.BRANCH_NODE,
    desc: "Make a user use the device",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 35 },
          { type: NodeType.ATTACK_VECTOR, index: 36 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Find a private key using a computational method",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 22 },
          { type: NodeType.ATTACK_VECTOR, index: 39 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Calculate a private key from signatures",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 23 },
          { type: NodeType.ATTACK_VECTOR, index: 38 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Find a random nonce of the signature",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 37 }],
  },

  {
    // 24
    type: NodeType.BRANCH_NODE,
    desc: "Manipulate a recipient address or amount of a transaction",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 25 },
              { type: NodeType.BRANCH_NODE, index: 26 },
              { type: NodeType.ATTACK_VECTOR, index: 53 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 27 },
              { type: NodeType.BRANCH_NODE, index: 28 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 29 },
              { type: NodeType.BRANCH_NODE, index: 30 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 85 },
              { type: NodeType.ATTACK_VECTOR, index: 142 },
            ],
          },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the app to generate a malicious transaction",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 40 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a user install the modified app",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 41 },
          { type: NodeType.ATTACK_VECTOR, index: 42 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the firmware to generate a malicious transaction",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 43 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a user install the modified firmware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 44 },
          { type: NodeType.ATTACK_VECTOR, index: 45 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the wallet device",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 46 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a user use the device",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 47 },
          { type: NodeType.ATTACK_VECTOR, index: 48 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the clipboard data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 49 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify memory data",
    children: [{ type: NodeType.BRANCH_NODE, index: 33 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 50 },
              { type: NodeType.ATTACK_VECTOR, index: 51 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 52 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Send cryptocurrency using a target device",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 54 },
          {
            $and: [{ type: NodeType.BRANCH_NODE, index: 35 }],
          },
          { type: NodeType.ATTACK_VECTOR, index: 62 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 55 },
          { type: NodeType.ATTACK_VECTOR, index: 56 },
          { type: NodeType.ATTACK_VECTOR, index: 57 },
          { type: NodeType.ATTACK_VECTOR, index: 58 },
          { type: NodeType.BRANCH_NODE, index: 36 },
          { type: NodeType.ATTACK_VECTOR, index: 61 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Brute-force attack",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 59 },
          { type: NodeType.ATTACK_VECTOR, index: 60 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Show an adversary's address as an user's address",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 38 },
          { type: NodeType.BRANCH_NODE, index: 40 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Manipulate memory data",
    children: [{ type: NodeType.BRANCH_NODE, index: 39 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 63 },
              { type: NodeType.ATTACK_VECTOR, index: 64 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 65 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Manipulate output data",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 41 },
              { type: NodeType.BRANCH_NODE, index: 42 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 43 },
              { type: NodeType.BRANCH_NODE, index: 44 },
            ],
          },
          {
            $and: [
              { type: NodeType.BRANCH_NODE, index: 45 },
              { type: NodeType.BRANCH_NODE, index: 46 },
            ],
          },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the firmware to manipulate output data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 66 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a user install the modified firmware",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 67 },
          { type: NodeType.ATTACK_VECTOR, index: 68 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify app to manipulate output data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 69 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Make a user install the modified app",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 70 },
          { type: NodeType.ATTACK_VECTOR, index: 71 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Modify the wallet device to manipulate output data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 72 }],
  },

  {
    //46
    type: NodeType.BRANCH_NODE,
    desc: "Make a user use the device",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 73 },
          { type: NodeType.ATTACK_VECTOR, index: 74 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Delete a private key",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 48 },
          { type: NodeType.BRANCH_NODE, index: 51 },
          { type: NodeType.BRANCH_NODE, index: 54 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Delete a private key using the app function",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 75 },
          { type: NodeType.BRANCH_NODE, index: 49 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 76 },
          { type: NodeType.ATTACK_VECTOR, index: 77 },
          { type: NodeType.ATTACK_VECTOR, index: 78 },
          { type: NodeType.ATTACK_VECTOR, index: 79 },
          { type: NodeType.BRANCH_NODE, index: 50 },
          { type: NodeType.ATTACK_VECTOR, index: 82 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Brute-force attack",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 80 },
          { type: NodeType.ATTACK_VECTOR, index: 81 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Delete data in storage(Flash, HDD, SSD)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 145 },
          { type: NodeType.BRANCH_NODE, index: 52 },
          { type: NodeType.BRANCH_NODE, index: 53 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Disk formatting or factory reset",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 83 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 84 },
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 85 },
              { type: NodeType.ATTACK_VECTOR, index: 86 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 87 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Lock the device",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 88 },
          { type: NodeType.ATTACK_VECTOR, index: 89 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Encrypt files in the storage",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 90 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Delete the app",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 57 },
          { type: NodeType.BRANCH_NODE, index: 58 },
          { type: NodeType.BRANCH_NODE, index: 59 },
          { type: NodeType.ATTACK_VECTOR, index: 146 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Uninstall the app",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 91 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 92 },
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 93 },
              { type: NodeType.ATTACK_VECTOR, index: 94 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 95 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Disk formatting or factory reset",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 96 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Encrypt files in the storage",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 97 }],
  },

  {
    //61
    type: NodeType.BRANCH_NODE,
    desc: "Man-in-the-middle attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 98 },
          { type: NodeType.ATTACK_VECTOR, index: 99 },
          { type: NodeType.ATTACK_VECTOR, index: 100 },
        ],
      },
    ],
  },

  {
    //62
    type: NodeType.BRANCH_NODE,
    desc: "Obtain account information from the app",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 102 },
          { type: NodeType.BRANCH_NODE, index: 63 },
          { type: NodeType.ATTACK_VECTOR, index: 110 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 103 },
          { type: NodeType.ATTACK_VECTOR, index: 104 },
          { type: NodeType.ATTACK_VECTOR, index: 105 },
          { type: NodeType.ATTACK_VECTOR, index: 106 },
          { type: NodeType.BRANCH_NODE, index: 64 },
          { type: NodeType.ATTACK_VECTOR, index: 109 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Brute-force attack",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 107 },
          { type: NodeType.ATTACK_VECTOR, index: 108 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Obtain account information when a user uses the app",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 66 },
          { type: NodeType.BRANCH_NODE, index: 67 },
          { type: NodeType.BRANCH_NODE, index: 68 },
          { type: NodeType.BRANCH_NODE, index: 69 },
        ],
      },
    ],
  },

  {
    // 66
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop input data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 111 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop output data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 112 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Read the clipboard data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 113 }],
  },

  {
    // 69
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop network traffic",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 114 },
          { type: NodeType.BRANCH_NODE, index: 88 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Obtain user's personally identifiable information from data storage",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 71 },
          { type: NodeType.BRANCH_NODE, index: 73 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Read data at rest(Flash, HDD, SSD",
    children: [
      {
        $or: [
          {
            $or: [
              { type: NodeType.ATTACK_VECTOR, index: 115 },
              { type: NodeType.ATTACK_VECTOR, index: 116 },
              { type: NodeType.ATTACK_VECTOR, index: 117 },
            ],
          },
          { type: NodeType.BRANCH_NODE, index: 72 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Read data at rest(Flash, HDD, SSD)",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 118 },
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 119 },
              { type: NodeType.ATTACK_VECTOR, index: 120 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 121 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Read data at rest(Flash, HDD, SSD",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 122 },
          { type: NodeType.BRANCH_NODE, index: 74 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Gain root or admin privilege",
    children: [
      {
        $or: [
          {
            $and: [
              { type: NodeType.ATTACK_VECTOR, index: 123 },
              { type: NodeType.ATTACK_VECTOR, index: 124 },
            ],
          },
          { type: NodeType.ATTACK_VECTOR, index: 125 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Get user's personally identifiable information from the app",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 126 },
          { type: NodeType.BRANCH_NODE, index: 76 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Bypass wallet user authentication",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 127 },
          { type: NodeType.ATTACK_VECTOR, index: 128 },
          { type: NodeType.ATTACK_VECTOR, index: 129 },
          { type: NodeType.ATTACK_VECTOR, index: 130 },
          { type: NodeType.BRANCH_NODE, index: 77 },
          { type: NodeType.ATTACK_VECTOR, index: 133 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Brute-force attack",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 131 },
          { type: NodeType.ATTACK_VECTOR, index: 132 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc:
      "Get user's personally identifiable information when a user uses the app",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 79 },
          { type: NodeType.BRANCH_NODE, index: 80 },
          { type: NodeType.BRANCH_NODE, index: 81 },
          { type: NodeType.BRANCH_NODE, index: 82 },
          { type: NodeType.BRANCH_NODE, index: 83 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop input data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 134 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop output data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 135 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Read the clipboard data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 136 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop peripheral device communication data",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 137 }],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Eavesdrop network traffic",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 138 },
          { type: NodeType.BRANCH_NODE, index: 84 },
        ],
      },
    ],
  },

  {
    type: NodeType.BRANCH_NODE,
    desc: "Man-in-the-middle attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 139 },
          { type: NodeType.ATTACK_VECTOR, index: 140 },
          { type: NodeType.ATTACK_VECTOR, index: 141 },
        ],
      },
    ],
  },

  {
    // 85
    type: NodeType.BRANCH_NODE,
    desc: "Manipulate the transaction by other process",
    children: [
      {
        $or: [
          { type: NodeType.BRANCH_NODE, index: 31 },
          { type: NodeType.BRANCH_NODE, index: 32 },
        ],
      },
    ],
  },

  {
    // 86
    type: NodeType.BRANCH_NODE,
    desc: "Replace a user's address to an adversary's",
    children: [{ type: NodeType.BRANCH_NODE, index: 87 }],
  },

  {
    // 87
    type: NodeType.BRANCH_NODE,
    desc: "Replace an address using a clipboard malware",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 143 },
          { type: NodeType.ATTACK_VECTOR, index: 144 },
        ],
      },
    ],
  },

  {
    // 88
    type: NodeType.BRANCH_NODE,
    desc: "Man-in-the-middle attack",
    children: [
      {
        $or: [
          { type: NodeType.ATTACK_VECTOR, index: 147 },
          { type: NodeType.ATTACK_VECTOR, index: 148 },
          { type: NodeType.ATTACK_VECTOR, index: 149 },
        ],
      },
    ],
  },

  {
    // Test
    // B. 86
    type: NodeType.BRANCH_NODE,
    desc: "Passive attack",
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
    // C. 87
    type: NodeType.BRANCH_NODE,
    desc: "Observe the screen directly",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 147 }],
  },

  {
    // D. 88
    type: NodeType.BRANCH_NODE,
    desc: "Read data from key storage",
    children: [{ type: NodeType.ATTACK_VECTOR, index: 148 }],
  },

  {
    // E. 89
    type: NodeType.BRANCH_NODE,
    desc: "Passive attack with a keylogger",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 143 },
          { type: NodeType.ATTACK_VECTOR, index: 144 },
        ],
      },
    ],
  },

  {
    // F. 90
    type: NodeType.BRANCH_NODE,
    desc: "Passive attack with a clipboard hijacker",
    children: [
      {
        $and: [
          { type: NodeType.ATTACK_VECTOR, index: 145 },
          { type: NodeType.ATTACK_VECTOR, index: 146 },
        ],
      },
    ],
  },
];

// Attack Vectors
export const attacks: Node[] = [
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a keylogger(keyboard, mouse, and touch screen input)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Shoulder-surfing(smartphone camera, surveillance camera)",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Access the wallet when it is unlocked",
    cvssScore: TH_ACCESS_WHEN_UNLOCKED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Guess",
    cvssScore: TH_GUESS,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Dump credential files",
    cvssScore: TH_DUMP_FILES,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack on authentication credentials",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Physical attacks(e.g., fault injection)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    //10
    type: NodeType.ATTACK_VECTOR,
    desc: "Obtain passphrase",
    cvssScore: TH_OBTAIN_PASSPHRASE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Shoulder-surfing(smartphone camera, surveillance camera)",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(screen capture)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Connect a debugger(JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Physical attacks(e.g., probing and reverse engineering)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(e.g., Trojan)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass access control for key files",
    cvssScore: TH_BYPASS_ACCESS_CONTROL,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Brute-force attack on an encrypted private key or recovery phrase",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "RowHammer Attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    //20
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Cold boot attack",
    cvssScore: TH_COLD_BOOT,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(capture the clipboard data)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    //30
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineering",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineering",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_HW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attack",
    cvssScore: TH_HW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineering(e.g., fake product website)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Find two signatures with the same random value",
    cvssScore: TH_FIND_SAME_SIGNATURES,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    //40
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineering",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attac",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineering",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_HW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attac",
    cvssScore: TH_HW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineering(e.g., fake product website)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    //50
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass wallet user confirmation",
    cvssScore: TH_BYPASS_USER_CONFIRMATION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Shoulder-surfing(smartphone camera, surveillance camera)",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Access the wallet when it is unlocked",
    cvssScore: TH_ACCESS_WHEN_UNLOCKED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Guess",
    cvssScore: TH_GUESS,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Dump credential files",
    cvssScore: TH_DUMP_FILES,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack on authentication credentials",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Physical attacks(e.g., fault injection)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Obtain passphrase",
    cvssScore: TH_OBTAIN_PASSPHRASE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineerin",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_SW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attack",
    cvssScore: TH_SW_SUPPLY_CHAIN,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineerin",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Reverse engineering",
    cvssScore: TH_HW_REVERSE_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Supply chain attack",
    cvssScore: TH_HW_SUPPLY_CHAIN,
  },
  {
    //74
    type: NodeType.ATTACK_VECTOR,
    desc: "Social engineering(e.g., fake product website)",
    cvssScore: TH_SOCIAL_ENGINEERING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Shoulder-surfing(including smartphone camera, surveillance camera)",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Access the wallet when it is unlocked",
    cvssScore: TH_ACCESS_WHEN_UNLOCKED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Guess",
    cvssScore: TH_GUESS,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    //80
    type: NodeType.ATTACK_VECTOR,
    desc: "Dump credential files",
    cvssScore: TH_DUMP_FILES,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack on authentication credentials",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Physical attacks(e.g., fault injection)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Access the target device physically",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "RowHammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Try invalid PIN or password until it is locked",
    cvssScore: TH_TRY_INVALID_PIN,
  },
  {
    //90
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(ransomware)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "RowHammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Access the target device physically",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(ransomware)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "DNS spoofing",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    //100
    type: NodeType.ATTACK_VECTOR,
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "DDoS attack on the blockchain API server",
    cvssScore: TH_DDoS_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Shoulder-surfing(including smartphone camera, surveillance camera)",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Access the wallet when it is unlocked",
    cvssScore: TH_ACCESS_WHEN_UNLOCKED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Guess",
    cvssScore: TH_GUESS,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack on authentication credentials",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Dump credential files",
    cvssScore: TH_DUMP_FILES,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack on authentication credentials",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Physical attacks(e.g., fault injection",
    cvssScore: TH_ACCESS_PHYSICALLY,
  },
  {
    //110
    type: NodeType.ATTACK_VECTOR,
    desc: "Obtain passphrase",
    cvssScore: TH_OBTAIN_PASSPHRASE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(keylogger)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(screen capture)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(capture clipboard data)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(capture network packets)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Connect a debugger(JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Physical attacks(e.g., probing and reverse engineering)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "RowHammer attack",
    cvssScore: TH_ROWHAMMER,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    //120
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Cold boot attack",
    cvssScore: TH_COLD_BOOT,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc:
      "Buffer overflow attack on vulnerable programs with root or admin privilege",
    cvssScore: TH_BUFFER_OVERFLOW,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Code injection(shellcode)",
    cvssScore: TH_CODE_INJECTION,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware on a rooted device",
    cvssScore: TH_INSTALL_MALWARE_ON_ROOTED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass OS authentication",
    cvssScore: TH_BYPASS_OS_AUTH,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Shoulder-surfing(smartphone camera, surveillance camera)",
    cvssScore: TH_SHOULDER_SURFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Access the wallet when it is unlocked",
    cvssScore: TH_ACCESS_WHEN_UNLOCKED,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Guess",
    cvssScore: TH_GUESS,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Evil maid attack",
    cvssScore: TH_EVIL_MAID,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Dump credential files",
    cvssScore: TH_DUMP_FILES,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bruce-force attack on authentication credentials",
    cvssScore: TH_BRUTE_FORCE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Physical attacks(e.g., fault injection)",
    cvssScore: TH_PHYSICAL_ATTACK,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(keylogger)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(screen capture)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(capture clipboard data)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(e.g., USB data logger)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a malware(capture network packets)",
    cvssScore: TH_INSTALL_MALWARE,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "DNS spoofing",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    // 140
    type: NodeType.ATTACK_VECTOR,
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },
  {
    type: NodeType.ATTACK_VECTOR,
    desc: "Bypass wallet user confirmation",
    cvssScore: TH_BYPASS_USER_CONFIRMATION,
  },
  {
    // 143
    type: NodeType.ATTACK_VECTOR,
    desc: "Install a clipboard malware",
    cvssScore: [AV.L, AC.M, PR.N, UI.R, TC.M],
  },
  {
    // 144
    type: NodeType.ATTACK_VECTOR,
    desc: "Clipboard malware",
    cvssScore: [AV.N, AC.L, PR.N, UI.R, TC.L],
  },

  {
    // 145
    type: NodeType.ATTACK_VECTOR,
    desc: "Connect a debugger(JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    // 146
    type: NodeType.ATTACK_VECTOR,
    desc: "Connect a debugger(JTAG, SWD)",
    cvssScore: TH_CONNECT_DEBUGGER,
  },
  {
    //147
    type: NodeType.ATTACK_VECTOR,
    desc: "DNS spoofing",
    cvssScore: TH_DNS_SPOOFING,
  },
  {
    //148
    type: NodeType.ATTACK_VECTOR,
    desc: "IP address spoofing",
    cvssScore: TH_IP_ADDR_SPOOFING,
  },
  {
    //149
    type: NodeType.ATTACK_VECTOR,
    desc: "ARP spoofing",
    cvssScore: TH_ARP_SPOOFING,
  },

  {
    // test
    // G 143
    type: NodeType.ATTACK_VECTOR,
    desc: "G. Install a keylogger",
    // cvssScore: [AV.L, AC.M, PR.L, UI.R, TC.M],
    cvssScore: [AV.L, AC.H, PR.L, UI.R, TC.M],
  },
  {
    // H 144
    type: NodeType.ATTACK_VECTOR,
    desc: "H. Keylogging",
    // cvssScore: [AV.N, AC.L, PR.N, UI.R, TC.L],
    cvssScore: [AV.L, AC.H, PR.N, UI.R, TC.L],
  },
  {
    // I 145
    type: NodeType.ATTACK_VECTOR,
    desc: "I. Install a clipboard hijacker",
    // cvssScore: [AV.L, AC.M, PR.N, UI.R, TC.M],
    cvssScore: [AV.L, AC.H, PR.N, UI.R, TC.M],
  },
  {
    // J 146
    type: NodeType.ATTACK_VECTOR,
    desc: "J. Clipboard hijacking",
    // cvssScore: [AV.N, AC.L, PR.N, UI.R, TC.L],
    cvssScore: [AV.L, AC.H, PR.N, UI.R, TC.L],
  },
  {
    // K 147
    type: NodeType.ATTACK_VECTOR,
    desc: "K. Shoulder-surfing attack",
    cvssScore: [AV.P, AC.H, PR.N, UI.R, TC.M],
  },
  {
    // L 148
    type: NodeType.ATTACK_VECTOR,
    desc: "L. Physcial attack",
    // cvssScore: [AV.P, AC.H, PR.N, UI.N, TC.H],
    cvssScore: [AV.P, AC.H, PR.N, UI.N, TC.E],
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
    resultNode.name = `SG${index}`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      type: "Sub Goal",
      desc: node.desc,
    });
  } else if (node.type === NodeType.BRANCH_NODE) {
    resultNode.name = `N${index}`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      type: "Branch Node",
      desc: node.desc,
    });
  } else if (node.type === NodeType.ATTACK_VECTOR) {
    resultNode.name = `A${index}`;
    resultNode.attributes = Object.assign(resultNode.attributes, {
      type: "Attack Vector",
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
