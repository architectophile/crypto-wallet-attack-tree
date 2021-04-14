import { RawNodeDatum } from "react-d3-tree/lib/types/common";

export enum NodeType {
  ROOT_GOAL,
  SUB_GOAL,
  BRANCH_NODE,
  ATTACK_VECTOR,
  OR,
  AND,
}

export interface OperatorOr {
  $or: NodeInfoX[];
}

export interface OperatorAnd {
  $and: NodeInfoX[];
}

export interface NodeInfo {
  type: NodeType;
  index: number;
}

export type NodeInfoX = NodeInfo | OperatorOr | OperatorAnd;

export interface Node {
  type: NodeType;
  desc: string;
  children?: NodeInfoX[];
  cvssScore?: number[];
}

export enum DeviceType {
  EMBEDDED_SYSTEM,
  MOBILE_ANDROID,
  PC,
}

export interface DeviceInfo {
  type: DeviceType;
  name: string;
  productRemoved: RemovedNodes;
  productImpacted: ImpactedNodes;
}

interface NodeState {
  [key: string]: number;
}

interface CvssBaseState {
  [key: string]: number[];
}

export interface RemovedNodes {
  goals: NodeState;
  subgoals: NodeState;
  branchnodes: NodeState;
  attacks: NodeState;
}

export interface ImpactedNodes {
  goals: NodeState;
  subgoals: NodeState;
  branchnodes: NodeState;
  attacks: CvssBaseState;
}

export interface NewNodeDatum extends RawNodeDatum {
  cvssScore: number;
  children?: NewNodeDatum[];
}
