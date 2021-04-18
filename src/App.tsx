import "./App.css";
import Tree from "react-d3-tree";
import { RawNodeDatum } from "react-d3-tree/lib/types/common";
import {
  addBNInfo,
  generateAttackTree,
  sortNetwork,
} from "./threat-model/node-data";
import {
  deviceBread,
  deviceCopay,
  deviceElectrum,
  deviceLedger,
  deviceTrezor,
  deviceTrust,
} from "./threat-model/device-data";
import { INetwork, infer, inferAll } from "bayesjs";
import { NetworkContainer } from "./threat-model/common";

const g1TreeLedger: RawNodeDatum = generateAttackTree(deviceLedger, 1);
const g1TreeTrezor: RawNodeDatum = generateAttackTree(deviceTrezor, 1);
const g1TreeBread: RawNodeDatum = generateAttackTree(deviceBread, 1);
const g1TreeTrust: RawNodeDatum = generateAttackTree(deviceTrust, 1);
const g1TreeCopay: RawNodeDatum = generateAttackTree(deviceCopay, 1);
const g1TreeElectrum: RawNodeDatum = generateAttackTree(deviceElectrum, 1);

const g2TreeLedger: RawNodeDatum = generateAttackTree(deviceLedger, 2);
const g2TreeTrezor: RawNodeDatum = generateAttackTree(deviceTrezor, 2);
const g2TreeBread: RawNodeDatum = generateAttackTree(deviceBread, 2);
const g2TreeTrust: RawNodeDatum = generateAttackTree(deviceTrust, 2);
const g2TreeCopay: RawNodeDatum = generateAttackTree(deviceCopay, 2);
const g2TreeElectrum: RawNodeDatum = generateAttackTree(deviceElectrum, 2);

const g3TreeLedger: RawNodeDatum = generateAttackTree(deviceLedger, 3);
const g3TreeTrezor: RawNodeDatum = generateAttackTree(deviceTrezor, 3);
const g3TreeBread: RawNodeDatum = generateAttackTree(deviceBread, 3);
const g3TreeTrust: RawNodeDatum = generateAttackTree(deviceTrust, 3);
const g3TreeCopay: RawNodeDatum = generateAttackTree(deviceCopay, 3);
const g3TreeElectrum: RawNodeDatum = generateAttackTree(deviceElectrum, 3);

const networkContainer: NetworkContainer = {
  network: {},
};

const g1BNLedger: RawNodeDatum = addBNInfo(g1TreeLedger, networkContainer);
// const N130Infer = infer(network, { 'N130': 'T' }).toFixed(4);
// const N131Infer = infer(network, { 'N131': 'T' }).toFixed(4);
// const N132Infer = infer(network, { 'N132': 'T' }).toFixed(4);
// const N133Infer = infer(network, { 'N133': 'T' }).toFixed(4);
// const N134Infer = infer(network, { 'N134': 'T' }).toFixed(4);
// const AND0 = infer(network, { 'AND0': 'T' }).toFixed(4);
// const AND1 = infer(network, { 'AND1': 'T' }).toFixed(4);
const networkStr = JSON.stringify(networkContainer.network);
sortNetwork(networkContainer);
const networkStr2 = JSON.stringify(networkContainer.network);

console.log("networkStr: " + networkStr);
const result = inferAll(networkContainer.network, {}, { force: true });
// const N129 = infer(network, { 'N129': 'T' }).toFixed(4);
// const SG9 = infer(network, { 'SG9': 'T' }).toFixed(4);
// const G1 = infer(network, { 'G1': 'T' }).toFixed(4);
const network2: INetwork = JSON.parse(networkStr);
const result2 = inferAll(networkContainer.network, {}, { force: true });
console.log("network :", networkContainer.network);

const networkTest: INetwork = {
  T336: {
    cpt: { T: 0.3, F: 0.7 },
    id: "T336",
    states: ["T", "F"],
    parents: [],
  },
  T337: {
    cpt: { T: 0.27, F: 0.73 },
    id: "T337",
    states: ["T", "F"],
    parents: [],
  },
  T338: {
    cpt: { T: 0.18, F: 0.82 },
    id: "T338",
    states: ["T", "F"],
    parents: [],
  },
  T339: {
    cpt: { T: 0.13, F: 0.87 },
    id: "T339",
    states: ["T", "F"],
    parents: [],
  },
  T340: {
    cpt: { T: 0.53, F: 0.47 },
    id: "T340",
    states: ["T", "F"],
    parents: [],
  },
  B129: {
    cpt: [
      { when: { B130: "T" }, then: { T: 1, F: 0 } },
      { when: { B130: "F" }, then: { T: 0, F: 1 } },
    ],
    id: "B129",
    states: ["T", "F"],
    parents: ["B130"],
  },
  B130: {
    cpt: [
      { when: { AND0: "T" }, then: { T: 1, F: 0 } },
      { when: { AND0: "F" }, then: { T: 0, F: 1 } },
    ],
    id: "B130",
    states: ["T", "F"],
    parents: ["AND0"],
  },
  B131: {
    cpt: [
      {
        when: { T336: "T", T337: "T", T338: "T", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "T", T338: "T", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "T", T337: "F", T338: "T", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "F", T338: "T", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "T", T337: "T", T338: "F", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "T", T338: "F", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "T", T337: "F", T338: "F", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "F", T338: "F", T339: "T" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "T", T337: "T", T338: "T", T339: "F" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "T", T338: "T", T339: "F" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "T", T337: "F", T338: "T", T339: "F" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "F", T338: "T", T339: "F" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "T", T337: "T", T338: "F", T339: "F" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "T", T338: "F", T339: "F" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "T", T337: "F", T338: "F", T339: "F" },
        then: { T: 1, F: 0 },
      },
      {
        when: { T336: "F", T337: "F", T338: "F", T339: "F" },
        then: { T: 0, F: 1 },
      },
    ],
    id: "B131",
    states: ["T", "F"],
    parents: ["T336", "T337", "T338", "T339"],
  },
  G1: {
    cpt: [
      { when: { S9: "T" }, then: { T: 1, F: 0 } },
      { when: { S9: "F" }, then: { T: 0, F: 1 } },
    ],
    id: "G1",
    states: ["T", "F"],
    parents: ["S9"],
  },
  S9: {
    cpt: [
      { when: { B129: "T" }, then: { T: 1, F: 0 } },
      { when: { B129: "F" }, then: { T: 0, F: 1 } },
    ],
    id: "S9",
    states: ["T", "F"],
    parents: ["B129"],
  },
  AND0: {
    cpt: [
      { when: { B131: "T", T340: "T" }, then: { T: 1, F: 0 } },
      { when: { B131: "F", T340: "T" }, then: { T: 0, F: 1 } },
      { when: { B131: "T", T340: "F" }, then: { T: 0, F: 1 } },
      { when: { B131: "F", T340: "F" }, then: { T: 0, F: 1 } },
    ],
    id: "AND0",
    states: ["T", "F"],
    parents: ["B131", "T340"],
  },
};

const networkTestStr = JSON.stringify(networkTest);
console.log("networkTestStr: " + networkTestStr);
const result3 = inferAll(networkTest, {}, { force: true });

const networkTest2 = {
  T336: {
    id: "T336",
    states: ["T", "F"],
    parents: [],
    cpt: { T: 0.3, F: 0.7 },
  },
  T337: {
    id: "T337",
    states: ["T", "F"],
    parents: [],
    cpt: { T: 0.27, F: 0.73 },
  },
  T338: {
    id: "T338",
    states: ["T", "F"],
    parents: [],
    cpt: { T: 0.18, F: 0.82 },
  },
  T339: {
    id: "T339",
    states: ["T", "F"],
    parents: [],
    cpt: { T: 0.13, F: 0.87 },
  },
  T340: {
    id: "T340",
    states: ["T", "F"],
    parents: [],
    cpt: { T: 0.53, F: 0.47 },
  },
  B129: {
    id: "B129",
    states: ["T", "F"],
    parents: ["B130"],
    cpt: [
      { when: { B130: "T" }, then: { T: 1, F: 0 } },
      { when: { B130: "F" }, then: { T: 0, F: 1 } },
    ],
  },
  B130: {
    id: "B130",
    states: ["T", "F"],
    parents: ["AND0"],
    cpt: [
      { when: { AND0: "T" }, then: { T: 1, F: 0 } },
      { when: { AND0: "F" }, then: { T: 0, F: 1 } },
    ],
  },
  S9: {
    id: "S9",
    states: ["T", "F"],
    parents: ["B129"],
    cpt: [
      { when: { B129: "T" }, then: { T: 1, F: 0 } },
      { when: { B129: "F" }, then: { T: 0, F: 1 } },
    ],
  },
  G1: {
    id: "G1",
    states: ["T", "F"],
    parents: ["S9"],
    cpt: [
      { when: { S9: "T" }, then: { T: 1, F: 0 } },
      { when: { S9: "F" }, then: { T: 0, F: 1 } },
    ],
  },
  AND0: {
    id: "AND0",
    states: ["T", "F"],
    parents: ["B131", "T340"],
    cpt: [
      { when: { B131: "T", T340: "T" }, then: { T: 1, F: 0 } },
      { when: { B131: "F", T340: "T" }, then: { T: 0, F: 1 } },
      { when: { B131: "T", T340: "F" }, then: { T: 0, F: 1 } },
      { when: { B131: "F", T340: "F" }, then: { T: 0, F: 1 } },
    ],
  },
};

const result4 = inferAll(networkTest2, { T336: "F" }, { force: true });

console.log("this is for a breakpoint line.");

function App() {
  console.log("this is a breakpoint line.");

  return (
    <div className="App">
      <div id="treeWrapper" style={{ width: "500em", height: "500em" }}>
        <Tree data={g1BNLedger} orientation={"vertical"} />
      </div>
    </div>
  );
}

export default App;
