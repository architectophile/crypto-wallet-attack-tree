export enum CVSS_METRIC {
  AV,
  AC,
  PR,
  UI,
  TC,
  EX,
  EQ,
  C,
  I,
  A,
}

export interface CvssScoreMatrix {
  name: string;
  max: number;
  scores: number[];
}

export enum AV {
  N = 0,
  A = 1,
  L = 2,
  P = 3,
}

export enum AC {
  L = 0,
  M = 1,
  H = 2,
}

export enum PR {
  N = 0,
  L = 1,
  H = 2,
}

export enum UI {
  N = 0,
  R = 1,
}

export enum TC {
  N = 0,
  M = 1,
  H = 2,
  E = 3,
  X = 4,
}

export enum EX {
  L = 0,
  P = 1,
  E = 2,
  M = 3,
}

export enum EQ {
  S = 0,
  P = 1,
  B = 2,
  M = 3,
}

export const cvssMatrices: CvssScoreMatrix[] = [
  { name: "Attack Vector", max: 3, scores: [0.85, 0.62, 0.55, 0.2] },
  { name: "Access Complexity", max: 2, scores: [0.77, 0.62, 0.44] },
  { name: "Privilege Required", max: 2, scores: [0.85, 0.62, 0.27] },
  { name: "User Interaction", max: 1, scores: [0.85, 0.62] },
  { name: "Time Complexity", max: 4, scores: [0.85, 0.78, 0.42, 0.05, 0] },
  { name: "Expertise", max: 3, scores: [0.85, 0.53, 0.39, 0.33] },
  { name: "Equipment", max: 3, scores: [0.85, 0.47, 0.35, 0.3] },
];

export const calculateCvssBaseMtrics = (metricValues: number[]) => {
  let tempVal = 0;
  // get attack vector
  tempVal =
    metricValues[CVSS_METRIC.AV] > cvssMatrices[CVSS_METRIC.AV].max
      ? cvssMatrices[CVSS_METRIC.AV].max
      : metricValues[CVSS_METRIC.AV];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const avValue = cvssMatrices[CVSS_METRIC.AV].scores[tempVal];

  // get access complexity
  tempVal =
    metricValues[CVSS_METRIC.AC] > cvssMatrices[CVSS_METRIC.AC].max
      ? cvssMatrices[CVSS_METRIC.AC].max
      : metricValues[CVSS_METRIC.AC];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const acValue = cvssMatrices[CVSS_METRIC.AC].scores[tempVal];

  // get previlege required
  tempVal =
    metricValues[CVSS_METRIC.PR] > cvssMatrices[CVSS_METRIC.PR].max
      ? cvssMatrices[CVSS_METRIC.PR].max
      : metricValues[CVSS_METRIC.PR];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const prValue = cvssMatrices[CVSS_METRIC.PR].scores[tempVal];

  // get user interaction
  tempVal =
    metricValues[CVSS_METRIC.UI] > cvssMatrices[CVSS_METRIC.UI].max
      ? cvssMatrices[CVSS_METRIC.UI].max
      : metricValues[CVSS_METRIC.UI];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const uiValue = cvssMatrices[CVSS_METRIC.UI].scores[tempVal];

  // get time complexity
  tempVal =
    metricValues[CVSS_METRIC.TC] > cvssMatrices[CVSS_METRIC.TC].max
      ? cvssMatrices[CVSS_METRIC.TC].max
      : metricValues[CVSS_METRIC.TC];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const tcValue = cvssMatrices[CVSS_METRIC.TC].scores[tempVal];

  // get expertise
  tempVal =
    metricValues[CVSS_METRIC.EX] > cvssMatrices[CVSS_METRIC.EX].max
      ? cvssMatrices[CVSS_METRIC.EX].max
      : metricValues[CVSS_METRIC.EX];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const exValue = cvssMatrices[CVSS_METRIC.EX].scores[tempVal];

  // get equipment
  tempVal =
    metricValues[CVSS_METRIC.EQ] > cvssMatrices[CVSS_METRIC.EQ].max
      ? cvssMatrices[CVSS_METRIC.EQ].max
      : metricValues[CVSS_METRIC.EQ];
  tempVal = tempVal < 0 ? 0 : tempVal;
  const eqValue = cvssMatrices[CVSS_METRIC.EQ].scores[tempVal];

  const result = 3.44 * avValue * acValue * prValue * uiValue * tcValue * exValue * eqValue;
  return result;
};
