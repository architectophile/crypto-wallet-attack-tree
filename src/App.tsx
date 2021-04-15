import './App.css';
import Tree from "react-d3-tree";
import { RawNodeDatum } from 'react-d3-tree/lib/types/common';
import { generateAttackTree } from "./threat-model/node-data";
import { deviceBread, deviceCopay, deviceElectrum, deviceLedger, deviceTrezor, deviceTrust } from './threat-model/device-data';

const g1TreeLedger : RawNodeDatum = generateAttackTree(deviceLedger, 1);
const g1TreeTrezor : RawNodeDatum = generateAttackTree(deviceTrezor, 1);
const g1TreeBread : RawNodeDatum = generateAttackTree(deviceBread, 1);
const g1TreeTrust : RawNodeDatum = generateAttackTree(deviceTrust, 1);
const g1TreeCopay : RawNodeDatum = generateAttackTree(deviceCopay, 1);
const g1TreeElectrum : RawNodeDatum = generateAttackTree(deviceElectrum, 1);

const g2TreeLedger : RawNodeDatum = generateAttackTree(deviceLedger, 2);
const g2TreeTrezor : RawNodeDatum = generateAttackTree(deviceTrezor, 2);
const g2TreeBread : RawNodeDatum = generateAttackTree(deviceBread, 2);
const g2TreeTrust : RawNodeDatum = generateAttackTree(deviceTrust, 2);
const g2TreeCopay : RawNodeDatum = generateAttackTree(deviceCopay, 2);
const g2TreeElectrum : RawNodeDatum = generateAttackTree(deviceElectrum, 2);

const g3TreeLedger : RawNodeDatum = generateAttackTree(deviceLedger, 3);
const g3TreeTrezor : RawNodeDatum = generateAttackTree(deviceTrezor, 3);
const g3TreeBread : RawNodeDatum = generateAttackTree(deviceBread, 3);
const g3TreeTrust : RawNodeDatum = generateAttackTree(deviceTrust, 3);
const g3TreeCopay : RawNodeDatum = generateAttackTree(deviceCopay, 3);
const g3TreeElectrum : RawNodeDatum = generateAttackTree(deviceElectrum, 3);

function App() {
  console.log("this is the breakpoint line.");

  return (
    <div className="App">
      <div id="treeWrapper" style={{ width: '500em', height: '500em' }}>
        <Tree 
          data={g1TreeCopay}
          orientation={"vertical"}/>
      </div>
    </div>
  );
}

export default App;
